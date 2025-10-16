# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy the csproj and restore as distinct layers
COPY ["Src/IdentityService/IdentityService/IdentityService.csproj", "Src/IdentityService/IdentityService/"]
RUN dotnet restore "Src/IdentityService/IdentityService/IdentityService.csproj"

# Copy everything else and build
COPY . .
WORKDIR "/src/Src/IdentityService/IdentityService"
RUN dotnet publish -c Release -o /app/out

# Stage 2: Run
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/out .
ENTRYPOINT ["dotnet", "IdentityService.dll"]
