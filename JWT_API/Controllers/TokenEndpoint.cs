using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public static class TokenEndpoint
{
    private static readonly IResult badRequest = TypedResults.BadRequest(new { Error = "Invalid Request" });

    public static async Task<IResult> Connect(HttpContext ctx, JwtOptions jwtOptions)
    {
        // validates the content type of the request
        if (ctx.Request.ContentType != "application/x-www-form-urlencoded")
            return badRequest;

        var formCollection = await ctx.Request.ReadFormAsync();

        // pulls information from the form
        if (formCollection.TryGetValue("grant_type", out _) == false)
            return badRequest;

        if (formCollection.TryGetValue("username", out var userName) == false)
            return badRequest;

        if (formCollection.TryGetValue("password", out _) == false)
            return badRequest;

        //creates the access token (jwt token)
        var tokenExpiration = TimeSpan.FromSeconds(jwtOptions.ExpirationSeconds);
        var accessToken = CreateAccessToken(
            jwtOptions,
            userName!,
            TimeSpan.FromMinutes(60),
            new[] { "read", "create", "delete" }); 

        // returns a json response with the access token
        return Results.Ok(new
        {
            access_token = accessToken,
            expiration = (int)tokenExpiration.TotalSeconds,
            type = "bearer"
        });
    }

    private static string CreateAccessToken(JwtOptions jwtOptions, string username, TimeSpan expiration, string[] permissions)
    {
        var keyBytes = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);
        var symmetricKey = new SymmetricSecurityKey(keyBytes);
        var signingCredentials = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>()
        {
            new ("sub", username),
            new ("name", username),
            new ("aud", jwtOptions.Audience)
        };

        var roleClaims = permissions.Select(x => new Claim("role", x));
        claims.AddRange(roleClaims);

        var token = new JwtSecurityToken(
            issuer: jwtOptions.Issuer,
            audience: jwtOptions.Audience,
            claims: claims,
            expires: DateTime.Now.Add(expiration),
            signingCredentials: signingCredentials);

        var rawToken = new JwtSecurityTokenHandler().WriteToken(token);

        return rawToken;
    }
}