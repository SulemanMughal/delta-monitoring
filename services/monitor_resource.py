import psutil

# Get CPU Usage
cpu_usage = psutil.cpu_percent(interval=1)

# Get Memory Usage
memory_usage = psutil.virtual_memory().percent

print(f"CPU Usage: {cpu_usage}%")
print(f"Memory Usage: {memory_usage}%")