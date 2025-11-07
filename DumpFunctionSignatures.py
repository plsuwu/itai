# @description ghidra script to decompile and dump exported function signatures from a PE
# @author plsuwu
# @category _NEW_
# @keybinding
# @menupath
# @toolbar

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor


def get_exported_functions():
    exported_functions = []
    symbol_table = currentProgram.getSymbolTable()

    symbols = symbol_table.getAllSymbols(True)

    for symbol in symbols:
        if (
            symbol.getSymbolType() == SymbolType.FUNCTION
            and symbol.isExternalEntryPoint()
        ):
            func = getFunctionAt(symbol.getAddress())
            if func is not None:
                exported_functions.append(func)

    return exported_functions


def decompile_and_get_signature(func, decompiler):
    results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())

    if results is None or not results.decompileCompleted():
        print("decompilation failure: {}".format(func.getName()))
        return None

    high_func = results.getHighFunction()
    if high_func is None:
        return None

    decomp_func = results.getDecompiledFunction()
    if decomp_func is not None:
        signature = decomp_func.getSignature()
        return signature

    return func.getPrototypeString(False, False)


def main():
    if currentProgram is None:
        return

    from java.io import File

    output_file = (
        File(currentProgram.getExecutablePath()).getParent() + "/exports_signatures.txt"
    )
    # output_file = File("exported_functions.txt", "w")

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    exported_funcs = get_exported_functions()

    if not exported_funcs:
        print("failed to retrieve exported functions")
        decompiler.dispose()
        return

    print("{} exported functions queued for decompilation".format(len(exported_funcs)))

    successful = 0
    with open(output_file, "w") as f:
        f.write("exported functions: {}\n".format(currentProgram.getName()))
        f.write("-" * 10 + "\n\n")

        for i, func in enumerate(exported_funcs):
            print(
                "decompiling [{}/{}]: {}".format(
                    i + 1, len(exported_funcs), func.getName()
                )
            )

            signature = decompile_and_get_signature(func, decompiler)
            address = func.getEntryPoint()

            if signature:
                output_line = "0x{}: {}\n".format(address, signature)
                f.write(output_line)
                successful += 1
            else:
                fallback_sig = func.getPrototypeString(False, False)
                output_line = "0x{}: {} (decompilation failure)\n".format(
                    address, fallback_sig
                )
                f.write(output_line)

            print("  {}".format(signature if signature else "FAILED"))

        f.write("\n" + "-" * 10 + "\n")
        f.write("processed {} total functions\n".format(len(exported_funcs)))
        f.write("({} successful)\n".format(successful))

    decompiler.dispose()

    print(
        "\nexported {} function signatures: {}".format(len(exported_funcs), output_file)
    )


if __name__ == "__main__":
    main()
