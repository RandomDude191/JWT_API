using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

internal class Program
{
    private static void Main(string[] args)
    {
        // Source: https://rmauro.dev/jwt-authentication-with-csharp-dotnet/
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddControllers();
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var jwtOptions = builder.Configuration
            .GetSection("JwtOptions")
            .Get<JwtOptions>() ?? throw new Exception("Konnte keine JWT Optionen auslesen.");

        builder.Services.AddSingleton(jwtOptions);

        // Configuring the Authentication Service
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(opts =>
            {
                //convert the string signing key to byte array
                var signingKeyBytes = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);

                opts.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ValidAudience = jwtOptions.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes)
                };
            });

        // Configuring the Authorization Service
        builder.Services.AddAuthorization();

        var app = builder.Build();

        // This add the Authentication Middleware
        app.UseAuthentication();
        // This add the Authorization Middleware
        app.UseAuthorization();

        //// The routes / and /public allow anonymous requests
        //app.MapGet("/", () => "Hello World!");
        //app.MapGet("/public", () => "Public Hello World!")
        //    .AllowAnonymous();

        //// The routes /private require authorized request
        //app.MapGet("/private", () => "Private Hello World!")
        //    .RequireAuthorization();

        //// handles the request token endpoint
        // In this case .NET 6 is capable of returning a IResult
        //app.MapPost("/tokens/connect", (HttpContext ctx, JwtOptions jwtOptions)
        //    => TokenEndpoint.Connect(ctx, jwtOptions));

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();
        app.MapControllers();
        app.Run();
    }
}