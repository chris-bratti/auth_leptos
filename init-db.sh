#!/bin/sh
# Creates database "daily" if it doesn't already exist
echo "Creating databse"
if psql -h leptos_postgres -U master -tc "SELECT 1 FROM pg_database WHERE datname = 'daily'" | grep -q 1; then
    echo "Database already exists"
else
    psql -h leptos_postgres -U master -c "CREATE DATABASE daily"
fi

if psql -h leptos_postgres -U master -b daily -tc  "SELECT 1 from information_schema.tables where table_name = 'users'" | grep -q 1; then
    echo "Tables already exist"
else
    psql -h leptos_postgres -U master -b daily -f init.sql
fi

echo "Starting the application..."
exec /app/auth_leptos