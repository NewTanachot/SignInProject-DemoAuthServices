using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using SignInProject.Authorization;
using System.Text;
using WebApp.Data;

var builder = WebApplication.CreateBuilder(args);
ConfigurationManager Configuration = builder.Configuration;

// Add services to the container.

// Add Controller
builder.Services.AddControllers();

// Add DbContext
builder.Services.AddDbContext<UserDataDbContext>(options =>
{
    options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));
});

// Add Identity
builder.Services.AddIdentity<IdentityUser, IdentityRole>(option =>
{
    option.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

    // Essential Password Option
    option.Password.RequireNonAlphanumeric = false;
    option.Password.RequireDigit = false;
    option.Password.RequireUppercase = false;

    // Check duplicate Email
    option.User.RequireUniqueEmail = true;
}).AddEntityFrameworkStores<UserDataDbContext>(); ;

// Add Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(builder.Configuration.GetValue<string>("SecretKey"))),
        ValidateLifetime = true,
        ValidateAudience = false,
        ValidateIssuer = false,
        ClockSkew = TimeSpan.Zero
    };
}); 

// Add Authorixation ( Add Policy )
builder.Services.AddAuthorization(option =>
{
    // need to Add IAuthorizationHandler
    option.AddPolicy("AuthorizeAll", policy => {
        policy.Requirements.Add(new AdultOnly(18));
        policy.RequireClaim("Permission", "View"); 
    });
});

// Add IAuthorizationHandler for custom Handler
builder.Services.AddSingleton<IAuthorizationHandler, AdultOnlyHandler>();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add NewtonSoft
builder.Services.AddControllersWithViews().AddNewtonsoftJson(options =>
{
    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
}).AddNewtonsoftJson(options => options.SerializerSettings.ContractResolver = new DefaultContractResolver());

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Use(async (context, next) =>
{
    await context.Response.WriteAsync("1. Hello from 1nd delegate.\n");
    Console.WriteLine("First here");
    await next();
    Console.WriteLine("Last Here");
    await context.Response.WriteAsync("2. Hello from 1nd delegate.\n");
});

app.Run(async context =>
{
    await context.Response.WriteAsync("Hello from 2nd delegate.\n");
});

app.Run();

