using IdentityAspNetCore;
using IdentityAspNetCore.Authorize;
using IdentityAspNetCore.Data;
using IdentityAspNetCore.Models;
using IdentityAspNetCore.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Build.Experimental;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();


builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireDigit = false;

    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    options.SignIn.RequireConfirmedEmail = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = $"/Account/Login";
    options.LogoutPath = $"/Account/Logout";
    options.AccessDeniedPath = $"/Account/AccessDenied";
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminCreate", policy => policy.RequireRole(SD.Role_Admin).RequireClaim("Create", ["True"]));

    options.AddPolicy("UserOver1000", p => p.Requirements.Add(new UserWithOver1000DaysRegisteredRequirement(1000)));
});

builder.Services.AddScoped<IAuthorizationHandler, UserWithOver1000DaysRegisteredHandler>();

builder.Services.AddScoped<IUserOver1000, UserOver1000>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
