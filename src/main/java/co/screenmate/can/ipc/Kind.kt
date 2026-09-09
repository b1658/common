package co.screenmate.can.ipc

/**
 * VHAL value kinds. Retained from the (removed) LocalSocket protocol because the vendor-signal
 * catalog [co.screenmate.can.privileged.VendorSignals] tags each signal with its kind. The live
 * transport is now [co.screenmate.can.privileged.PrivilegedBroadcastClient] (broadcasts), which
 * carries only INT32/FLOAT on the wire; the other kinds remain here for the catalog's metadata.
 */
object Kind {
    const val INT32: Byte = 0
    const val FLOAT: Byte = 1
    const val BOOL: Byte = 2
    const val STRING: Byte = 3
    const val INT32_VEC: Byte = 4
    const val INT64: Byte = 5
    const val UNKNOWN: Byte = -1
}
