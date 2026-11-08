package app.example.patches

import app.reseam.patch.CompatiblePackage
import app.reseam.patch.dex.*
import app.reseam.patch.klass
import app.reseam.patch.patch
import app.reseam.patch.types.FieldRef
import app.reseam.patch.types.MethodRef

val interstitialPatch =
    patch("Disable interstitial readiness") {
        compatibleWith(CompatiblePackage("com.duolingo", listOf("6.104.5")))
        execute {
            val method = klass("Lf7l;").classDef.methods.single { it.name == "a" && it.proto == "()Z" }
            require(
                method.dexIndex == 4 && method.info.accessFlags == 0x11u &&
                    !method.isStatic && method.registersSize == 3 && method.insSize == 1,
            )
            val instructions = method.instructions
            require(
                instructions.size == 26 && instructions.sumOf {
                    when (it.opcode) {
                        Opcode.CONST_4, Opcode.MOVE_RESULT, Opcode.MOVE_RESULT_OBJECT,
                        Opcode.RETURN,
                        -> 1

                        Opcode.IGET_OBJECT, Opcode.CHECK_CAST, Opcode.INSTANCE_OF,
                        Opcode.IF_NEZ,
                        -> 2

                        Opcode.INVOKE_VIRTUAL -> 3

                        else -> error("Unexpected readiness opcode: ${it.opcode}")
                    }
                } == 49,
            )
            // Identify only the automatic interstitial coordinator's readiness dependencies.
            require(
                instructions.mapNotNull { it.fieldRef } ==
                    listOf(
                        FieldRef("Lf7l;", "b", "Lyd0;"),
                        FieldRef("Lyd0;", "c", "Ljava/lang/Object;"),
                        FieldRef("Lyd0;", "d", "Ljava/lang/Object;"),
                        FieldRef("Lyd0;", "b", "Ljava/lang/Object;"),
                        FieldRef("Lyd0;", "f", "Ljava/lang/Object;"),
                    ),
            )
            val getValue = MethodRef("Lxt40;", "getValue", "()Ljava/lang/Object;")
            require(
                instructions.mapNotNull { it.methodRef } ==
                    listOf(getValue, getValue, MethodRef("Llth;", "i", "()Z"), getValue),
            )
            require(
                instructions.mapNotNull { it.typeRef } ==
                    listOf("Lxt40;", "Lk7l;", "Lxt40;", "Lmsh;", "Llth;", "Lxt40;", "Lawh;"),
            )
            // shortcut: try metadata is externally checked on the pinned XAPK; recheck before reuse.
            method.replaceBody(
                3,
                0,
                buildInstructions {
                    constInt(0, 0)
                    returnValue(0)
                },
            )
        }
    }
