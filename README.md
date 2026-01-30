# flametui 

![how it looks to use flametui](doc/preview.png)

This repository presents **flametui**, an experimental Linux system profiler that attempts to visualize stack traces as flamegraphs in the terminal. 
The fun part of this project is that it draws a flamegraph, in the TUI! 
This tool uses eBPF to hook into the Linux kernel's `perf_event` subsystem, sampling stack traces across CPUs. 
It tries to aggregate these traces in userspace and resolve them to human-readable symbols for visualization. 
I always found it a bit annoying to have to install a bunch of different tools to get a flamegraph. 
This tool aims to provide an all-in-one solution.

As a general disclaimer, this project is / was a huge learning experience for me.
This project has been insufficiently scrutenized to take its outputs as serious and correct. 
It looks cool though.

## Usage

As `vaxis` pins `0.15.1`, this is the required version. Note that we supply a flake.nix such that you can use my 
exact zig version if you care to!

```bash
# Build the project
zig build -Doptimize=ReleaseFast

# Run the profiler (requires root/CAP_BPF privileges)
# Sample at 49Hz for 1 second
sudo zig-out/bin/flametui --hz 49 --time 1000
```

*Note: Requires root privileges...!*

## Future Roadmap / Ideas

There are several areas where this project could be improved:

- [ ] **Libelf Integration**: I'm not sure, but using libbelf might be more robust than manually parsing it with `std.elf` from zig.
- [ ] **Streaming**: Currently, data collection and visualization are separate phases, so I want to implement streaming.
        This would allow us to view the graph evolve during profiling...! That's really cool. I am also keen to explore
        Further visualization options: moving-average flamegraphs, etc. 
- [ ] **Navigation**: Adding scrolling and zooming capabilities to handle larger traces.
- [ ] **Better UX**: Improving the overall responsiveness and interactivity. Currently, my vaxis impl. is giga janky.
