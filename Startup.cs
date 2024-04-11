using Groth16.Net;
using ProofService.interfaces;
using Serilog;
using Serilog.Formatting.Json;

namespace ProofService;

public class Startup
{
    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services)
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
        var configuration = builder.Build();
        var proverSetting = configuration.GetSection("ProverSetting").Get<ProverSetting>();
        Prover prover;
        if (File.Exists(proverSetting.WasmPath) && File.Exists(proverSetting.R1csPath) &&
            File.Exists(proverSetting.ZkeyPath))
        {
            prover = Prover.Create(proverSetting.WasmPath, proverSetting.R1csPath, proverSetting.ZkeyPath);
        }
        else
        {
            prover = new Prover();
        }
        
        // Dependency injection
        services.AddSingleton(prover);

        // Add framework services.
        services.AddControllers();
    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }

        app.UseHttpsRedirection();
        app.UseRouting();
        app.UseAuthorization();
        app.UseStaticFiles();
        app.UseDirectoryBrowser();

        // app.UseSwagger();
        // app.UseSwaggerUI();

        // Log configs
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console(new JsonFormatter())
            .WriteTo.File(new JsonFormatter(), "logs/GrothServiceLog-.log",
                rollingInterval: RollingInterval.Day, retainedFileCountLimit: 3,
                fileSizeLimitBytes: 2L * 1024 * 1024 * 1024)
            .CreateLogger();

        // Add Serilog to the logger factory
        loggerFactory.AddSerilog();

        app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
    }
}