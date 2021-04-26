using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
namespace DCNetStringDecryptor_CSharp
{
    class Program
    {
        private static int salt;
        static void Main(string[] args)
        {
            bool hideProcess = false;
            if (args.Contains("-hideProcess"))
            {
                hideProcess = true;
            }
            int stringPatchCount = 0;
            int stringFailedCount = 0;
            Console.Title = "DC.NET String Decryptor";
            Console.WriteLine("DC.NET String Decryptor by misonothx | sinister.ly <3");
            Console.WriteLine(" |- https://github.com/miso-xyz/DCNetStringDecryptor");
            Console.WriteLine(" |- https://github.com/dcsoft-yyf/DCNETProtector");
            Console.WriteLine();
            ModuleDefMD asm = ModuleDefMD.Load(args[0]);
            List<byte[]> vars = new List<byte[]>();
            Console.ForegroundColor = ConsoleColor.Yellow;
            if (!hideProcess)
            {
                Console.WriteLine("Retrieving encrypted bytes...");
            }
            Console.ForegroundColor = ConsoleColor.Green;
            foreach (var t_ in asm.Types)
            {
                if (t_.Namespace.Contains("_DC"))
                {
                    if (t_.Name.Contains("BytesContainer"))
                    {
                        foreach (var fields in t_.Fields)
                        {
                            if (fields.FieldType.TypeName.ToLower().Contains("_data"))
                            {
                                if (!hideProcess)
                                {
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.WriteLine("[Source Bytes]: '" + fields.Name + "' saved in memory...");
                                }
                                vars.Add(fields.InitialValue);
                            }
                        }
                    }
                    else
                    {
                        foreach (var methods in t_.Methods)
                        {
                            if (methods.Name == "dcsoft")
                            {
                                var intList = new List<int>();
                                foreach (Instruction inst in methods.Body.Instructions)
                                {
                                    if (inst.OpCode.Equals(OpCodes.Ldc_I4))
                                    {
                                        intList.Add(int.Parse(inst.Operand.ToString()));
                                    }
                                }
                                try
                                {
                                    salt = intList[1];
                                    if (!hideProcess)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.Write("Found Salt!");
                                        Console.ForegroundColor = ConsoleColor.Magenta;
                                        Console.WriteLine(" (" + intList[1] + ")");
                                    }
                                }
                                catch (Exception)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("Failed to retrieve salt!");
                                    Console.WriteLine();
                                    Console.WriteLine("The application cannot continue without being able to retrieve the salt!");
                                    Console.ResetColor();
                                    Console.Write("Press any key to exit...");
                                    Console.ReadKey();
                                    System.Environment.Exit(0);
                                }
                            }
                        }
                    }
                }
            }
            if (!hideProcess)
            {
                Console.WriteLine();
            }
            foreach (var t_ in asm.Types)
            {
                foreach (var methods in t_.Methods)
                {
                    if (t_.Namespace.Contains("_DC"))
                    {
                        if (methods.HasBody)
                        {
                            if (methods.Name == ".cctor")
                            {
                                CilBody fixedBody = new CilBody();
                                for (var x = 0; x < methods.Body.Instructions.Count; x++)
                                {
                                    switch (methods.Body.Instructions[x].OpCode.ToString())
                                    {
                                        case "ldc.i8":
                                            Instruction newInst = new Instruction(OpCodes.Ldstr, dcsoft(vars[0], long.Parse(methods.Body.Instructions[x].Operand.ToString())));
                                            Console.ForegroundColor = ConsoleColor.Yellow;
                                            if (!hideProcess)
                                            {
                                                Console.WriteLine("Decrypting '" + methods.Body.Instructions[x].Operand.ToString() + "'...");
                                            }
                                            try
                                            {
                                                fixedBody.Instructions.Add(newInst);
                                                fixedBody.Instructions.Add(methods.Body.Instructions[x + 2]);
                                                if (!hideProcess)
                                                {
                                                    Console.ForegroundColor = ConsoleColor.Green;
                                                    Console.Write("'" + methods.Body.Instructions[x].Operand.ToString() + "' decrypted!");
                                                    Console.ForegroundColor = ConsoleColor.Magenta;
                                                    Console.WriteLine(" (" + newInst.Operand.ToString() + ")");
                                                }
                                                stringPatchCount++;
                                            }
                                            catch (Exception)
                                            {
                                                if (!hideProcess)
                                                {
                                                    Console.ForegroundColor = ConsoleColor.Red;
                                                    Console.WriteLine("Failed to decrypt '" + methods.Body.Instructions[x].Operand.ToString() + "'");
                                                }
                                                stringFailedCount++;
                                            }
                                            if (!hideProcess)
                                            {
                                                Console.WriteLine();
                                            }
                                            break;
                                    }
                                }
                                fixedBody.Instructions.Add(new Instruction(OpCodes.Ret));
                                methods.Body = fixedBody;
                            }
                        }
                    }
                }
            }
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("######################################");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  " + stringPatchCount + " Strings Patched");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  " + stringFailedCount + " Strings Failed");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine("######################################");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Saving '" + System.IO.Path.GetFileNameWithoutExtension(args[0]) + "-DCNetStringsFixed" + System.IO.Path.GetExtension(args[0]) + "...");
            ModuleWriterOptions moduleWriterOptions = new ModuleWriterOptions(asm);
            moduleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            moduleWriterOptions.Logger = DummyLogger.NoThrowInstance;
            NativeModuleWriterOptions nativeModuleWriterOptions = new NativeModuleWriterOptions(asm, true);
            nativeModuleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
            nativeModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
            try
            {
                asm.Write(System.IO.Path.GetFileNameWithoutExtension(args[0]) + "-DCNetStringsFixed" + System.IO.Path.GetExtension(args[0]), moduleWriterOptions);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("File successfully saved!");
                Console.ReadKey();
            }
            catch (Exception)
            {
                throw;
            }
        }

        private static string dcsoft(byte[] datas, long key) // Taken from src
        {
            int num = (int)(key & 0xFFFFL) ^ salt;
            key >>= 0x10;
            int num2 = (int)(key & 0xFFFFFL);
            key >>= 0x18;
            int num3 = (int)key;
            char[] array = new char[num2];
            int i = 0;
            while (i < num2)
            {
                int num4 = i + num3 << 1;
                array[i] = (char)(((int)datas[num4] << 8) + (int)datas[num4 + 1] ^ num);
                i++;
                num++;
            }
            return new string(array);
        }

    }
}
