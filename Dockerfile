# Etapa de Build
FROM mcr.microsoft.com/dotnet/core/sdk:9.0 AS build

WORKDIR /src
COPY ["src/SteamOpenIdConnectProvider.csproj", "SteamOpenIdConnectProvider/"]
RUN dotnet restore "SteamOpenIdConnectProvider/SteamOpenIdConnectProvider.csproj"
COPY ["src/", "SteamOpenIdConnectProvider/"]
WORKDIR "/src/SteamOpenIdConnectProvider"
RUN dotnet build "SteamOpenIdConnectProvider.csproj" -c Release -o /app

# Etapa de Publicação
FROM build AS publish
RUN dotnet publish "SteamOpenIdConnectProvider.csproj" -c Release -o /app

# Etapa Final: Configurar Roteamento e Executar o 
FROM mcr.microsoft.com/dotnet/core/aspnet:9.0 AS base
WORKDIR /app

COPY --from=publish /app .

EXPOSE 80

HEALTHCHECK CMD curl --fail http://localhost/health || exit 1

# Define o entrypoint para configurar a rota antes de iniciar a aplicação
ENTRYPOINT ["/bin/bash", "-c", "\
    echo 'DEBUG: Starting container SteamOpenIdConnectProvider...'; \
    if [ -n \"$DEFAULT_GATEWAY\" ]; then \
        echo 'DEBUG: Setting new  Default Gateway: ' $DEFAULT_GATEWAY; \
        ip route del default || true; \
        ip route add default via $DEFAULT_GATEWAY; \
        echo 'DEBUG: New Routing Table:'; \
        ip route; \
    else \
        echo 'DEBUG: DEFAULT_GATEWAY não definido. Mantendo configuração padrão.'; \
    fi; \
    exec dotnet SteamOpenIdConnectProvider.dll"]