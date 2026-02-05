// This batch file reads database connection details from a .env file
// and sets them as environment variables before running dbt commands.bat

@echo off
for /f "tokens=1,2 delims==" %%a in (.env) do set %%a=%%b
cd dbt_project
dbt %*

