docker-compose restart kong && docker ps | grep kong:latest | awk '{print $1}' | xargs docker attach