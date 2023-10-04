
start.admin:
	cd insignia_backend && cargo run -- -m admin -p 6970

start.frontend:
	cd insignia_backend && cargo run -- -m frontend -p 6969
