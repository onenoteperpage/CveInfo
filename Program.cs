using Newtonsoft.Json;
using TextCopy;

namespace CveInfo
{
    internal class Program
    {
        [STAThread] // Required to use the Clipboard class
        static async Task Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: CveInfo <CVE_Code>");
                return;
            }

            string cveCode = args[0];
            string apiEndpoint = $"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveCode}";

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    HttpResponseMessage response = await client.GetAsync(apiEndpoint);

                    if (response.IsSuccessStatusCode)
                    {
                        dynamic jsonData = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync())!;

                        if (jsonData.vulnerabilities != null && jsonData.vulnerabilities.Count > 0)
                        {
                            foreach (var vulnerability in jsonData.vulnerabilities)
                            {
                                if (vulnerability.cve != null)
                                {
                                    var descriptions = vulnerability.cve.descriptions;

                                    if (descriptions != null)
                                    {
                                        foreach (var description in descriptions)
                                        {
                                            if (description.lang == "en")
                                            {
                                                Console.WriteLine(description.value);
                                                await ClipboardService.SetTextAsync(description.value.ToString());
                                                return; // Exit the application after finding the English description
                                            }
                                        }
                                    }
                                }
                            }
                            Console.WriteLine("English description not found.");
                        }
                        else
                        {
                            Console.WriteLine("No vulnerabilities found in the JSON.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Failed to fetch CVE information. Status code: " + response.StatusCode);
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine("Error fetching CVE information: " + ex.Message);
            }
        }
    }


    //string cveCode = args[0];
    //string apiEndpoint = $"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveCode}";

    //try
    //{
    //    using (HttpClient client = new HttpClient())
    //    {
    //        HttpResponseMessage response = await client.GetAsync(apiEndpoint);

    //        if (response.IsSuccessStatusCode)
    //        {
    //            string jsonContent = await response.Content.ReadAsStringAsync();

    //            // Deserialize the JSON response into the CveResult class
    //            CveResult cveResult = JsonConvert.DeserializeObject<CveResult>(jsonContent)!;

    //            if (cveResult != null)
    //            {
    //                Console.WriteLine($"CVE ID: {cveResult.vulnerabilities[0].cve.id}");
    //                Console.WriteLine($"Last Modified Date: {cveResult.timestamp}");
    //                Console.WriteLine($"CVE Description: {cveResult.vulnerabilities?.SelectMany(v => v.cve.descriptions)?.FirstOrDefault(desc => desc.lang == "en")?.value}");
    //            }
    //            else
    //            {
    //                Console.WriteLine("Failed to parse the API response.");
    //            }
    //        }
    //        else
    //        {
    //            Console.WriteLine("Failed to fetch CVE information. Status code: " + response.StatusCode);
    //        }
    //    }
    //}
    //catch (HttpRequestException ex)
    //{
    //    Console.WriteLine("Error fetching CVE information: " + ex.Message);
    //}
}