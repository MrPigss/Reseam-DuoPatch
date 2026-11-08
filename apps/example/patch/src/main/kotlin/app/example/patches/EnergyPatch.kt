package app.example.patches

import app.reseam.patch.CompatiblePackage
import app.reseam.patch.dex.*
import app.reseam.patch.klass
import app.reseam.patch.patch
import app.reseam.patch.types.FieldRef
import app.reseam.patch.types.Instruction

private const val energyOwner = "Lcom/duolingo/core/energy/models/EnergyConfig;"

val energyPatch =
    patch("Energy 25") {
        compatibleWith(CompatiblePackage("com.duolingo", listOf("6.104.5")))
        execute {
            val constructors = klass(energyOwner).classDef.directMethods.filter { it.name == "<init>" }
            val ordinary = constructors.single { it.proto == "(IIJJJIJLjava/lang/Integer;)V" }
            val synthetic = constructors.single { it.proto == "(IIIJJJIJLjava/lang/Integer;Z)V" }
            for (method in listOf(ordinary, synthetic)) {
                val serialized = method == synthetic
                val current = if (serialized) 5 else 1
                val receiver = if (serialized) 3 else 0
                val fullness = if (serialized) 4 else 1
                require(
                    !method.isStatic && method.registersSize == (if (serialized) 18 else 13) &&
                        method.insSize == (if (serialized) 15 else 13),
                )
                val instructions = method.instructions
                // Insert immediately before the current-energy assignment.
                require(
                    instructions[if (serialized) 5 else 1] ==
                        buildInstructions {
                            iput(current, receiver, FieldRef(energyOwner, "a", "I"))
                        }.single(),
                )
                // Fullness must still be computed from current == maximum.
                val equality = if (serialized) 25 else 9
                require(
                    instructions.subList(equality, equality + 6) ==
                        buildInstructions {
                            ifNe(current, current + 1, 4)
                            constInt(fullness, 1)
                            goto(2)
                            constInt(fullness, 0)
                            iput(fullness, receiver, FieldRef(energyOwner, "i", "Z"))
                            returnVoid()
                        },
                )
            }
            val instructions = synthetic.instructions
            // Required-field validation must precede the serialized overrides.
            require(
                instructions.take(3) ==
                    buildInstructions {
                        literal(Opcode.AND_INT_LIT8, 0, 0x3fL, 4)
                        constInt(1, 0)
                        constInt(2, 0x3f)
                    },
            )
            require(
                instructions[3].let {
                    it.opcode == Opcode.IF_NE && it.regA == 2 && it.regB == 0 &&
                        (it as Instruction.Branch2).field0.offset == 56
                },
            )
            require(instructions[38].opcode == Opcode.THROW && instructions[38].regA == 1)
            require(
                instructions[23].let {
                    it.opcode == Opcode.AND_INT_LIT16 && it.regA == 4 && it.regB == 4 && it.literal == 0x100L
                },
            )
            require(
                instructions[24].let {
                    it.opcode == Opcode.IF_NEZ && it.regA == 4 && (it as Instruction.Branch).field0.offset == 10
                },
            )
            require(
                instructions.subList(31, 34) ==
                    buildInstructions {
                        move(4, 17, "Z")
                        iput(4, 3, FieldRef(energyOwner, "i", "Z"))
                        returnVoid()
                    },
            )
            ordinary.insertInstructions(1, buildInstructions { constInt(1, 25) })
            synthetic.insertInstructions(
                5,
                buildInstructions {
                    constInt(5, 25)
                    // Clear serialized fullness after required-field validation, then recompute it.
                    literal(Opcode.AND_INT_LIT16, 4, -257L, 4)
                },
            )
        }
    }
