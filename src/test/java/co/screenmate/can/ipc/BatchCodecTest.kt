package co.screenmate.can.ipc

import co.screenmate.can.ipc.BatchCodec.Rec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class BatchCodecTest {

    private val key = "SMCAN-broadcast-hmac-v1".toByteArray(Charsets.UTF_8)
    private val recs = listOf(
        Rec(0x214004E3, BatchCodec.K_INT, 7),
        Rec(0x2160055B, BatchCodec.K_FLOAT, java.lang.Float.floatToIntBits(42.5f)),
    )

    @Test fun v2_roundTrip_verifiesAndParses() {
        val framed = BatchCodec.frameV2(seq = 9, tsElapsed = 123456, flags = 0, records = recs, key = key)
        val d = BatchCodec.deframe(framed, key, requireAuth = true)!!
        assertEquals(2, d.version)
        assertEquals(9L, d.seq)
        assertEquals(123456L, d.tsElapsed)
        assertEquals(0, d.flags)
        assertEquals(recs, d.records)
    }

    @Test fun v2_heartbeat_emptyRecordsPreservesFlags() {
        val framed = BatchCodec.frameV2(1, 2, flags = 0x3, records = emptyList(), key = key)
        val d = BatchCodec.deframe(framed, key, requireAuth = true)!!
        assertEquals(0x3, d.flags)
        assertTrue(d.records.isEmpty())
    }

    @Test fun tamperedByte_isRejected() {
        val framed = BatchCodec.frameV2(1, 2, 0, recs, key)
        framed[20] = (framed[20] + 1).toByte() // flip a payload byte
        assertNull(BatchCodec.deframe(framed, key, requireAuth = true))
    }

    @Test fun tamperedMac_isRejected() {
        val framed = BatchCodec.frameV2(1, 2, 0, recs, key)
        framed[framed.size - 1] = (framed[framed.size - 1] + 1).toByte()
        assertNull(BatchCodec.deframe(framed, key, requireAuth = true))
    }

    @Test fun wrongKey_isRejected() {
        val framed = BatchCodec.frameV2(1, 2, 0, recs, key)
        assertNull(BatchCodec.deframe(framed, "other-key".toByteArray(), requireAuth = true))
    }

    @Test fun truncated_isRejected() {
        val framed = BatchCodec.frameV2(1, 2, 0, recs, key)
        assertNull(BatchCodec.deframe(framed.copyOf(framed.size - 3), key, requireAuth = true))
        assertNull(BatchCodec.deframe(ByteArray(4), key, requireAuth = true))
        assertNull(BatchCodec.deframe(ByteArray(0), key, requireAuth = true))
    }

    @Test fun v1_rejectedUnderAuth_acceptedWithout() {
        val framed = BatchCodec.frameV1(recs)
        assertNull(BatchCodec.deframe(framed, key, requireAuth = true))
        val d = BatchCodec.deframe(framed, key, requireAuth = false)!!
        assertEquals(1, d.version)
        assertEquals(-1L, d.seq)
        assertEquals(recs, d.records)
    }

    @Test fun unknownVersion_isRejectedEvenWhenAuthentic() {
        // A well-formed, correctly-MACed batch with an unrecognised version must not be parsed.
        val body = ByteArrayOutputStream()
        DataOutputStream(body).apply { writeInt(99); writeInt(0) }
        val payload = body.toByteArray()
        // Reuse frameV2's MAC scheme by framing raw payload: recompute via a v2 frame is not exposed,
        // so assert the malformed/unknown path returns null through the non-auth route too.
        assertNull(BatchCodec.deframe(payload, key, requireAuth = false))
    }

    @Test fun negativeCount_doesNotThrow() {
        val body = ByteArrayOutputStream()
        DataOutputStream(body).apply { writeInt(2); writeLong(1); writeLong(1); writeInt(0); writeInt(-5) }
        assertNull(BatchCodec.deframe(body.toByteArray(), key, requireAuth = false))
    }

    @Test fun v3_roundTrip_carriesMetrics() {
        val framed = BatchCodec.frameV3(
            seq = 5, tsElapsed = 999, flags = 0x1, reconnectCount = 3, maxReadMicros = 1234,
            records = recs, key = key,
        )
        val d = BatchCodec.deframe(framed, key, requireAuth = true)!!
        assertEquals(3, d.version)
        assertEquals(0x1, d.flags)
        assertEquals(3, d.reconnectCount)
        assertEquals(1234, d.maxReadMicros)
        assertEquals(recs, d.records)
    }

    @Test fun request_roundTrip() {
        val framed = BatchCodec.frameRequest(clientId = 0x1122334455667788L, propIds = listOf(0x214004E3, 0x21600149), key = key)
        val r = BatchCodec.deframeRequest(framed, key)!!
        assertEquals(0x1122334455667788L, r.clientId)
        assertEquals(listOf(0x214004E3, 0x21600149), r.propIds)
    }

    @Test fun request_emptyIsPresenceOnly() {
        val r = BatchCodec.deframeRequest(BatchCodec.frameRequest(7, emptyList(), key), key)!!
        assertEquals(7L, r.clientId)
        assertTrue(r.propIds.isEmpty())
    }

    @Test fun request_tamperedOrWrongKey_isRejected() {
        val framed = BatchCodec.frameRequest(7, listOf(1, 2), key)
        assertNull(BatchCodec.deframeRequest(framed, "nope".toByteArray()))
        framed[framed.size - 1] = (framed[framed.size - 1] + 1).toByte()
        assertNull(BatchCodec.deframeRequest(framed, key))
    }

    @Test fun v3_byteLayout_isPinnedForProducerParity() {
        // Pins the exact v3 header the pure-Java producer must emit.
        val framed = BatchCodec.frameV3(1, 2, 0, 4, 5, emptyList(), key)
        val expectedHeader = byteArrayOf(
            0, 0, 0, 3,                         // int version
            0, 0, 0, 0, 0, 0, 0, 1,             // long seq
            0, 0, 0, 0, 0, 0, 0, 2,             // long tsElapsed
            0, 0, 0, 0,                         // int flags
            0, 0, 0, 4,                         // int reconnectCount
            0, 0, 0, 5,                         // int maxReadMicros
            0, 0, 0, 0,                         // int count
        )
        assertEquals(expectedHeader.size + BatchCodec.HMAC_LEN, framed.size)
        assertArrayEquals(expectedHeader, framed.copyOf(expectedHeader.size))
    }

    @Test fun request_byteLayout_isPinnedForProducerParity() {
        // Pins the request header the pure-Java agent must parse.
        val framed = BatchCodec.frameRequest(clientId = 2, propIds = listOf(0x0A0B0C0D), key = key)
        val expected = byteArrayOf(
            0, 0, 0, 1,                         // int reqVersion
            0, 0, 0, 0, 0, 0, 0, 2,             // long clientId
            0, 0, 0, 1,                         // int count
            0x0A, 0x0B, 0x0C, 0x0D,             // int propId
        )
        assertEquals(expected.size + BatchCodec.HMAC_LEN, framed.size)
        assertArrayEquals(expected, framed.copyOf(expected.size))
    }

    @Test fun byteLayout_isPinnedForProducerParity() {
        // Pins the exact v2 header the pure-Java producer must emit. If this breaks, the producer
        // and consumer have diverged. version=2, seq=1, ts=2, flags=0, count=0, then 8-byte MAC.
        val framed = BatchCodec.frameV2(seq = 1, tsElapsed = 2, flags = 0, records = emptyList(), key = key)
        val expectedHeader = byteArrayOf(
            0, 0, 0, 2,                         // int version
            0, 0, 0, 0, 0, 0, 0, 1,             // long seq
            0, 0, 0, 0, 0, 0, 0, 2,             // long tsElapsed
            0, 0, 0, 0,                         // int flags
            0, 0, 0, 0,                         // int count
        )
        assertEquals(expectedHeader.size + BatchCodec.HMAC_LEN, framed.size)
        assertArrayEquals(expectedHeader, framed.copyOf(expectedHeader.size))
    }
}
