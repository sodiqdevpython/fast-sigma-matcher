using System;
using System.IO;
using SigmaMatcherFast.Sigma;

namespace SigmaMatcherFast
{
    class Program
    {
        static int Main(string[] args)
        {
            string rulesDir = @"C:\Users\sodiq\Desktop\sigma2\rules";
            string logsDir = @"C:\Users\sodiq\Desktop\sigma2\rules\logs";

            using (var engine = new SigmaEngineFast(rulesDir))
            {
                engine.LoadRulePathsOnce(); // engine ni load qildim


                // Invalid rule larni ko'rsatishim uchun
                var invalids = engine.GetInvalidRules();
                Console.WriteLine($"INIT OK\nTotalRules={engine.RulePaths.Length}\nInvalidCount={invalids.Count}\nValidRules={engine.RulePaths.Length - invalids.Count}");

                if (invalids.Count > 0)
                {
                    Console.WriteLine("\nINVALID RULES:");
                    foreach (var inv in invalids)
                        Console.WriteLine(inv.Path + "\t" + inv.Error);
                    Console.WriteLine($"\nYuqoridagi {invalids.Count} ta invalid rule lar edi ular matching qilishda hisobga olinmaydi tashlab ketiladi\n");
                }

                // Batch uchun namuna folder berib yuboriladi ichidagi hammasini bittalab matching qilib chiqadi
                var files = Directory.GetFiles(logsDir, "*.jsonl", SearchOption.AllDirectories);
                Array.Sort(files, StringComparer.OrdinalIgnoreCase);

                foreach (var file in files)
                {
                    // includeLine bo'lsa tezroq ishlaydi chunki ayni shu rule qaysi log ga tegishli ekanligini olib kelmaydi uni hit.FilePath bilan hit.LineNo dan ham topib olsa bo'ladi
                    engine.ScanJsonlFile(file, includeLine: true, onHit: hit =>
                    {
                        Console.WriteLine($"\n{hit.FilePath} => {hit.LineNo} => {hit.RuleIndex} => {hit.RulePath} => {hit.Line}");
                    });
                }
            }

            Console.ReadKey();

            return 0;
        }   
    }
}
