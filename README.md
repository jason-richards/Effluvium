# Effluvium
docker build --tag effluvium .
docker run --name effluvium -p 5000:5000 --network host effluvium
