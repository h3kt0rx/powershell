

# Change foreground color to White
$host.UI.RawUI.ForegroundColor = "White"

# Change background color to Black
$host.UI.RawUI.BackgroundColor = "Black"

# Ensure OpenSSH is installed and available
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Error "SSH command not found. Please ensure OpenSSH is installed."
    exit
}

# Define the list of servers
$servers = @(
	"bluewing.local",
    "cloudflared.local",
    "code-server.local",
    "homeassistant.local",
    "homepage.local",
	"flaresolverr.local",
	"gamesystem.local",
    "immich.local",
    "jellyfin.local",
    "jellyseerr.local",
    "lancache.local",
    "mc01.local",
    "mc02.local",
	"mqtt.local",
    "netboot.local",
    "technitium1.local",
    "technitium2.local",
    "technitium.local",
	"passthough.local",
    "prowlarr.local",
	"pelican.local",
	"pelican-n1.local",
    "pterodactyl.local",
    "pterodactyln1.local",
    "qt.local",
    "radarr.local",
    "semaphore.local",
    "sonarr.local",
    "tailscale1.local",
    "tailscale2.local",
    "traefik.local",
    "uptimekuma.local",
    "vaultwarden.local"
)

# Define a list of colors
$colors = @(
    "Red", "Green", "Blue", "Cyan", "Magenta", "Yellow", "DarkGray", "Gray", "DarkGreen", "DarkCyan", "DarkMagenta", "DarkYellow"
)

# Function to display server list and connect via SSH with a specified user
function Connect-ToServer {
    # Display the list of servers with random colors and leading zero for single-digit numbers
    Write-Host "Available Servers:"
    Write-Host ""

    for ($i = 0; $i -lt $servers.Count; $i++) {
        # Format the index with leading zero if necessary
        $formattedIndex = "{0:D2}" -f ($i + 1)
        
        # Choose a random color from the list
        $randomColor = $colors[(Get-Random -Minimum 0 -Maximum $colors.Count)]
        
        # Set the foreground color
        $host.UI.RawUI.ForegroundColor = $randomColor
        
        # Print the server entry
        Write-Host "$formattedIndex. $($servers[$i])"
    }
    
    # Reset color to default
    $host.UI.RawUI.ForegroundColor = "White"
    
    Write-Host ""

    # Prompt the user to select a server
    $selection = Read-Host -Prompt "Enter the number of the server you want to connect to"

    # Validate the input
    if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $servers.Count) {
        $selectedServer = $servers[[int]$selection - 1]
        
        # Prompt for the SSH username
        $user = Read-Host -Prompt "Enter your SSH username"
        
        $sshCommand = "ssh $user@$selectedServer"
        Write-Host "Connecting to $selectedServer as $user..."
        
        # Establish SSH connection
        Start-Process -NoNewWindow -FilePath "ssh" -ArgumentList "$user@$selectedServer"

    } else {
        Write-Host "Invalid selection. Please enter a number between 01 and $($servers.Count.ToString("D2"))." -ForegroundColor Red
    }
}

# Execute the function
Connect-ToServer
