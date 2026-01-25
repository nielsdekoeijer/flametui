heavy wip, tui that makes flamegraph

# TODO
[ ] Refactor to use libelf. It's cool that I kinda made it work, but I think we should use the solver for the problem
[ ] Streaming flamegraphs. Refactor so that we stream data to the program while measuring. This should 
    prevent maps from getting full.
[ ] Realtime flamegraph updates
[ ] Add scrolling so you can scroll a theoretically big flamegraph
[ ] Add clicking to zoom, perhaps even have an easy built in zoom mechanism
[ ] Our profiler relies on certain optimization to not have been applied. 
