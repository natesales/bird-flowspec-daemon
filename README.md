# BIRD2 BGP FlowSpec router PoC

### Setup

The compose file and accompanying Dockerfile should be all you need to get started with a basic 2 router lab network. Running `docker-compose up` in the project directory will bring up 2 containers running BIRD: the controller to send flowspec routes and the router to communicate with the flowspecd process for acting upon the received routes.

```
controller - 10.5.0.2 AS65520
router - 10.5.0.3 AS65530
```
