FROM mcr.microsoft.com/dotnet/aspnet:8.0

WORKDIR /app
COPY bin/Release/net8.0/publish/ /app/

ENV ASPNETCORE_URLS=http://0.0.0.0:7020

ENTRYPOINT ["dotnet", "ProofService.dll"]