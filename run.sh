run_docker_cmd() {
    docker compose -f fakeauth/docker-compose.yaml $1
    docker compose -f some_app/docker-compose.yaml $1
    docker compose -f test_app/docker-compose.yaml $1
}

parse_args(){
    if [ $# -gt 1 ]; then
        echo "expect one of two args: up or down"
        exit 1
    fi

    case $1 in
        up) shift; run_docker_cmd "up --build -d";;
        down) shift; run_docker_cmd "down";;
    esac
}

parse_args $@
