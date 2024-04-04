using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using ProofService.interfaces;
using RestSharp;

namespace ProofService.controllers;

[Route("proof")]
[ApiController]
public class ProofController : ControllerBase
{
    private readonly ILogger<ProofController> _logger;
    // private readonly Prover _prover;
    private List<string> ExpectedPublicInputs = new List<string>
    {
        "127",
        "11",
        "219",
        "189",
        "91",
        "196",
        "198",
        "140",
        "33",
        "175",
        "230",
        "48",
        "103",
        "211",
        "155",
        "188",
        "134",
        "52",
        "50",
        "206",
        "194",
        "197",
        "107",
        "157",
        "53",
        "28",
        "173",
        "137",
        "52",
        "106",
        "139",
        "71",
        "5841544268561861499519250994748571",
        "282086110796185156675799806248152448",
        "2181169572700087019903500222780233598",
        "1322589976114836556068768894837633649",
        "1794113848426178665483863008905364300",
        "543380795324313410170505147425740531",
        "1493214249295981343844955353860051664",
        "2171199579242924905862250512208697455",
        "1395394319132308840130123038054629304",
        "1562009664380263536909338779810969578",
        "1594567849407226969396248621216777848",
        "2058356264851095114515728757906168363",
        "836769104848661443299826291369000556",
        "1779001964758400339025173335511101862",
        "2544058187525854999124570613534759403",
        "424565350689075956046563544271353450",
        "3799511822475913352444008446631779",
        "166",
        "119",
        "153",
        "147",
        "150",
        "220",
        "73",
        "162",
        "138",
        "214",
        "201",
        "194",
        "66",
        "113",
        "155",
        "179"
    };

    private string ProofStr =
        "e4f43e941f23f1478ffd459a9f6ec97e60ad790467bb9ffca97d7865ac5df09953cbaf72d64482095954e1770b249de00e405b2c5ac47b601850cac0939749183f8447be0c6b3e44e7bb61100b1f6b0fac038ea4f56271c45f2a3ebe79a367034aa423bf11f4dc3ab21440dd6642255d4a50d843a3db42fc3fa79852adec062f";

    public ProofController(ILogger<ProofController> logger)
    {
        _logger = logger;
        // _prover = prover;
    }

    [HttpPost("generate")]
    public IActionResult GenerateProof(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = request.Jwt;
            provingInput["signature"] = request.Signature;
            provingInput["pubkey"] = request.Pubkey;
            provingInput["salt"] = request.Salt;
            
            // var provingOutputString = _prover.ProveBn254(provingInput);
            // var provingOutput = ParseProvingOutput(provingOutputString);
            
            return StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse{ Proof = ProofStr});
        }
        catch (Exception e)
        {
            return StatusCode(500, e.Message);
        }
    }
    
    [HttpPost("generate2")]
    public IActionResult GenerateProof2(ProofGenerationSchema.ProofGenerationRequest2 request)
    {
        try
        {
            var jwtHeader = request.Jwt.Split(".")[0];
            var jwtPayload = request.Jwt.Split(".")[1];
            var jwtSignature = request.Jwt.Split(".")[2];

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(request.Jwt);
            
            var s = getGooglekid(jwt);
            parseJwtPayload(jwtPayload);
            
            // var identifierHash = Helpers.HexStringToByteArray(request.IdentifierHash);
            // var salt = Helpers.HexStringToByteArray(request.Salt);
            // var pk = Helpers.HexToChunkedBytes("", 121, 17)
            //     .Select(s => s.HexToBigInt()).ToList();
            //
            // byte[] decodedBytes = Convert.FromBase64String(jwtSignature);
            // var hexnew = BitConverter.ToString(decodedBytes).Replace("-", "").ToLower();
            // var sign = Helpers.HexToChunkedBytes(hexnew, 121, 17)
            //     .Select(s => s.HexToBigInt()).ToList();
            //
            // IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            // provingInput["jwt"] = PadString(jwtHeader + jwtPayload, 2048);
            // provingInput["signature"] = sign;
            // provingInput["pubkey"] = pk;
            // provingInput["salt"] = PadString(request.Salt, 32);
            //
            // var provingOutputString = _prover.ProveBn254(provingInput);
            // var provingOutput = ParseProvingOutput(provingOutputString);
            
            return StatusCode(200, new ProvingOutput(ExpectedPublicInputs, ProofStr));
        }
        catch (Exception e)
        {
            return StatusCode(500, e.Message);
        }
    }

    private static string parseJwtPayload(string payload)
    {
        string padded = payload.Length % 4 == 0 ? payload : payload + "====".Substring(payload.Length % 4);
        string base64 = padded.Replace("_", "/").Replace("-", "+");
        byte[] outputb = Convert.FromBase64String(base64);
        string outStr = Encoding.Default.GetString(outputb);
        Console.WriteLine(outStr);
        return outStr;
    }

    private static async Task getGooglekid(JwtSecurityToken jwt)
    {
        var kid = jwt.Header.Kid;
        
        var options = new RestClientOptions("https://www.googleapis.com/oauth2/v3/certs");
        var client = new RestClient(options);
        var request = new RestRequest("");
        var response = await client.GetAsync(request);
        if (!response.IsSuccessStatusCode)
        {
        }
    }

    private static ProvingOutput ParseProvingOutput(string provingOutput)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(provingOutput);
    }
    
    private static List<string> PadString(string str, int paddedBytesSize)
    {
        List<string> paddedBytes = str.Select(c => ((int)c).ToString()).ToList();

        int paddingLength = paddedBytesSize - paddedBytes.Count;
        if (paddingLength > 0)
        {
            paddedBytes.AddRange(Enumerable.Repeat("0", paddingLength));
        }

        return paddedBytes;
    }
    
}

public class ProvingOutput
{
    public ProvingOutput(IList<string> publicInputs, string proof)
    {
        PublicInputs = publicInputs;
        Proof = proof;
    }

    [JsonProperty("public_inputs")] public IList<string> PublicInputs { get; set; }

    [JsonProperty("proof")] public string Proof { get; set; }

    public static ProvingOutput FromJsonString(string jsonString)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(jsonString);
    }
}