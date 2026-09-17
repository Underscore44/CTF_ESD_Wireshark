$noms = & 'C:\Program Files\Wireshark\tshark.exe' `
  -r 'joueurs\soc_esd_racing.pcap' `
  -Y 'ip.src == 10.42.0.26 && ip.dst == 198.51.100.77 && dns.flags.response == 0' `
  -T fields -e dns.qry.name

$fragments = @{}

foreach ($nom in $noms) {
    $parties = $nom.Split('.')
    $index = [int]($parties[1].Split('-')[0])
    $fragments[$index] = $parties[2]
}

$donnees = ($fragments.Keys | Sort-Object | ForEach-Object {
    $fragments[$_]
}) -join ''

$donnees.ToUpperInvariant() |
  Set-Content -Path 'fragments.txt' -Encoding ascii