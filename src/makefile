.PHONY: build clean restore run publish

clean:
		dotnet clean ./AspNetCore.EncryptRequest.sln -nologo -consoleLoggerParameters:NoSummary -verbosity:quiet

restore:
		dotnet restore ./AspNetCore.EncryptRequest.sln

build:
		# dotnet build --verbosity minimal
		dotnet build ./AspNetCore.EncryptRequest.sln --no-restore /clp:ErrorsOnly

run: build
		dotnet run --project ./AspNetCore.EncryptRequest/AspNetCore.EncryptRequest.csproj --launch-profile "Dev" --property:Configuration=Debug

publish:
		# MSBuild.exe -clp:ErrorsOnly -nologo -m /property:Configuration=Release
		dotnet build --no-restore --configuration Release /clp:ErrorsOnly
		dotnet publish -c release -r centos.7-x64 --self-contained
		# dotnet publish -c release -r ubuntu.16.04-x64 --self-contained
		# The binary will be in "bin/Release/netcoreapp3.1/ubuntu.16.04-x64/publish"
