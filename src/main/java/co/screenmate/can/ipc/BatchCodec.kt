package co.screenmate.can.ipc

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure (no-Android) codec for the vendor-signal broadcast batch. Extracted here so the parse +
 * authentication path — the mission-critical, security-relevant part — is unit-testable on the JVM
 * and shared by the client instead of hand-inlined. The pure-Java producer (AgentBroadcaster) is
 * compiled standalone and cannot depend on this, so it mirrors [frameV2] by hand; BatchCodecTest
 * pins the exact byte layout so a producer/consumer divergence is caught by a test, not on-car.
 *
 * Wire v2 (framed): int version(=2), long seq, long tsElapsed, int flags, int count,
 * count×{ int id, byte kind, int bits }, then an 8-byte HMAC-SHA256 trailer over all preceding
 * bytes. v1 (int version(=1), int count, records; no MAC) is decoded only when auth is not required.
 * All integers are big-endian (DataOutput).
 */
object BatchCodec {

    /**
     * Current, FROZEN forward-batch version (see docs/PROTOCOL.md). A shipped version is never
     * mutated — the next change is v4 (reserved: rate tiering / changed-only). Producers emit exactly
     * this; consumers must also decode v2 during rollout and reject/ignore unknown-higher versions.
     */
    const val CURRENT_VERSION = 3
    const val REQUEST_VERSION = 1

    const val HMAC_LEN = 8
    const val K_INT: Byte = 0
    const val K_FLOAT: Byte = 1

    data class Rec(val id: Int, val kind: Byte, val bits: Int)
    data class Decoded(
        val version: Int,
        val seq: Long,
        val tsElapsed: Long,
        val flags: Int,
        val records: List<Rec>,
        val reconnectCount: Int = 0,  // v3+: cumulative Car rebuilds since producer start
        val maxReadMicros: Int = 0,   // v3+: worst per-signal read latency this cycle (µs)
    )

    /** A consumer→agent request/keepalive: announces presence and the wanted prop subset. */
    data class Request(val clientId: Long, val propIds: List<Int>)

    /** Encode a v3 batch (adds producer metrics) and append its HMAC trailer. */
    fun frameV3(
        seq: Long, tsElapsed: Long, flags: Int, reconnectCount: Int, maxReadMicros: Int,
        records: List<Rec>, key: ByteArray,
    ): ByteArray {
        val body = ByteArrayOutputStream(records.size * 9 + 40)
        DataOutputStream(body).apply {
            writeInt(3); writeLong(seq); writeLong(tsElapsed); writeInt(flags)
            writeInt(reconnectCount); writeInt(maxReadMicros); writeInt(records.size)
            records.forEach { writeInt(it.id); writeByte(it.kind.toInt()); writeInt(it.bits) }
        }
        return appendMac(body.toByteArray(), key)
    }

    /** Encode a consumer→agent request (reqVersion 1) with an HMAC trailer. */
    fun frameRequest(clientId: Long, propIds: List<Int>, key: ByteArray): ByteArray {
        val body = ByteArrayOutputStream(propIds.size * 4 + 24)
        DataOutputStream(body).apply {
            writeInt(1); writeLong(clientId); writeInt(propIds.size)
            propIds.forEach { writeInt(it) }
        }
        return appendMac(body.toByteArray(), key)
    }

    /** Verify + parse a consumer→agent request. Null on bad MAC / unknown version / malformed. */
    fun deframeRequest(framed: ByteArray, key: ByteArray): Request? {
        val body = verifyAndStrip(framed, key) ?: return null
        return try {
            val din = DataInputStream(ByteArrayInputStream(body))
            if (din.readInt() != 1) return null
            val clientId = din.readLong()
            val n = din.readInt()
            if (n < 0 || n > 4096) return null
            Request(clientId, List(n) { din.readInt() })
        } catch (_: Throwable) {
            null
        }
    }

    /** Encode a v2 batch and append its HMAC trailer. Mirrors the producer's on-wire layout. */
    fun frameV2(seq: Long, tsElapsed: Long, flags: Int, records: List<Rec>, key: ByteArray): ByteArray {
        val body = ByteArrayOutputStream(records.size * 9 + 32)
        DataOutputStream(body).apply {
            writeInt(2); writeLong(seq); writeLong(tsElapsed); writeInt(flags); writeInt(records.size)
            records.forEach { writeInt(it.id); writeByte(it.kind.toInt()); writeInt(it.bits) }
        }
        return appendMac(body.toByteArray(), key)
    }

    /** Encode a v1 batch (no MAC) — the legacy rollout format, retained for tests. */
    fun frameV1(records: List<Rec>): ByteArray {
        val body = ByteArrayOutputStream(records.size * 9 + 8)
        DataOutputStream(body).apply {
            writeInt(1); writeInt(records.size)
            records.forEach { writeInt(it.id); writeByte(it.kind.toInt()); writeInt(it.bits) }
        }
        return body.toByteArray()
    }

    /**
     * Verify (when [requireAuth]) and parse a framed batch. Returns null if the MAC does not check,
     * the version is unknown, or the bytes are malformed/truncated. Never throws.
     */
    fun deframe(framed: ByteArray, key: ByteArray, requireAuth: Boolean): Decoded? {
        val body = if (requireAuth) verifyAndStrip(framed, key) ?: return null else framed
        return try {
            val din = DataInputStream(ByteArrayInputStream(body))
            when (val version = din.readInt()) {
                1 -> {
                    if (requireAuth) return null // v1 carries no MAC; never trusted under auth
                    val n = din.readInt()
                    Decoded(1, -1, 0, 0, readRecords(din, n))
                }
                2 -> {
                    val seq = din.readLong()
                    val ts = din.readLong()
                    val flags = din.readInt()
                    val n = din.readInt()
                    Decoded(2, seq, ts, flags, readRecords(din, n))
                }
                3 -> {
                    val seq = din.readLong()
                    val ts = din.readLong()
                    val flags = din.readInt()
                    val reconnects = din.readInt()
                    val maxRead = din.readInt()
                    val n = din.readInt()
                    Decoded(3, seq, ts, flags, readRecords(din, n), reconnects, maxRead)
                }
                else -> null // unknown version: don't guess a layout
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun readRecords(din: DataInputStream, n: Int): List<Rec> {
        if (n < 0) throw IllegalStateException("negative count")
        val out = ArrayList<Rec>(minOf(n, 64))
        repeat(n) { out.add(Rec(din.readInt(), din.readByte(), din.readInt())) }
        return out
    }

    private fun appendMac(payload: ByteArray, key: ByteArray): ByteArray {
        val tag = hmac(payload, key)
        return payload + tag.copyOfRange(0, HMAC_LEN)
    }

    private fun verifyAndStrip(framed: ByteArray, key: ByteArray): ByteArray? {
        if (framed.size <= HMAC_LEN) return null
        val payloadLen = framed.size - HMAC_LEN
        val expected = hmac(framed.copyOfRange(0, payloadLen), key).copyOfRange(0, HMAC_LEN)
        val actual = framed.copyOfRange(payloadLen, framed.size)
        return if (MessageDigest.isEqual(expected, actual)) framed.copyOfRange(0, payloadLen) else null
    }

    private fun hmac(data: ByteArray, key: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
}
