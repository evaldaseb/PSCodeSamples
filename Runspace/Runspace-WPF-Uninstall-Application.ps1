$uiHash = [hashtable]::Synchronized(@{})
$newRunspace =[runspacefactory]::CreateRunspace()
$newRunspace.ApartmentState = 'STA'
$newRunspace.ThreadOptions = 'ReuseThread'          
$newRunspace.Open()
$newRunspace.SessionStateProxy.SetVariable('uiHash',$uiHash)          
$psCmd = [PowerShell]::Create().AddScript({   
    $uiHash.Error = $Error
    [xml]$xaml = @"
    <Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="Window" Title="Initial Window" WindowStartupLocation = "CenterScreen"
        Width = "400" Height = "300" ShowInTaskbar = "True">
        <Grid>
        <Button
                Name="btnStart" 
                Content="Start" 
                HorizontalAlignment="Left" 
                Margin="25,56,0,0" 
                VerticalAlignment="Top" 
                Width="75"
             />
             <ProgressBar 
                Name="ProgressBar" 
                Height="20"
                Width="120"
                HorizontalAlignment="Left" 
                VerticalAlignment="Top" 
                Margin = "25,100,0,0"
                IsIndeterminate="True"
                Visibility="Collapsed"
             />
        </Grid>
    </Window>
"@
    [void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')   
    $reader=(New-Object System.Xml.XmlNodeReader $xaml)
    $uiHash.Window=[Windows.Markup.XamlReader]::Load( $reader )
    $uiHash.Button = $uiHash.window.FindName('btnStart')
    $uiHash.ProgressBar = $uiHash.Window.FindName('ProgressBar')

    $uiHash.Button.Add_Click({
    $uiHash.Window.Dispatcher.BeginInvoke('Normal',[action]{$uiHash.ProgressBar.Visibility='Visible'})
    
    $InstallRunspace =[runspacefactory]::CreateRunspace()
    $InstallRunspace.ApartmentState = 'STA'         
    $InstallRunspace.Open()         
    $InstallRunspace.SessionStateProxy.SetVariable('uiHash',$uiHash)     
    
    $PowerShell = [PowerShell]::Create().AddScript({
        $Argument = ' -accepteula -s \\xpvm-eb05 cmd /c "msiexec /x {1D2365BD-CEAB-46EB-9F9A-D07F7FDB16D1} /qn"'

        $proc = start-process c:\psexec.exe -ArgumentList $Argument -PassThru
        while (-not $proc.HasExited)
        {
            Start-Sleep -Milliseconds 500
        }

        $uiHash.Window.Dispatcher.invoke('Normal',[action]{$uiHash.ProgressBar.Visibility='Collapsed'})    
    })
    
    $PowerShell.Runspace = $InstallRunspace
    $result = $PowerShell.BeginInvoke()
    
      
})

    $uiHash.Window.ShowDialog() | Out-Null
})
$psCmd.Runspace = $newRunspace
$handle = $psCmd.BeginInvoke()

#-----------------------------------------

$psCmd.EndInvoke($handle)
$psCmd.Dispose()
