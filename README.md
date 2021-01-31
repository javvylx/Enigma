# Introduction
The solution is aimed at providing as much information within the forensic bailiwick of an investigation. Our solution consists of 2 main categories, hardware and software. Under hardware, we will be utilizing the already pre-existing BashBunny to dump out the host machine’s RAM data and Event Logs, which will then be analyzed by our software solutions. <br>
<p align="center"><img src="https://raw.githubusercontent.com/vangeance666/Enigma/master/images/enigma.png" width=40% height=40%></p> <br>

<p align="center">

<img alt="Issues" src="https://img.shields.io/badge/Windows-Supported-brightgreen?style=flat&logo=windows">
<img alt="Issues" src="https://img.shields.io/badge/Hardware-BashBunny-informational?style=flat&logo=bashbunny">
<img alt="Issues" src="https://img.shields.io/badge/Python-v3.8.6-informational?style=flat&logo=python">
<img alt="Issues" src="https://img.shields.io/badge/Volatility-2.6-informational?style=flat&logo=volatility">
<img alt="Issues" src="https://img.shields.io/badge/Selenium-informational?style=flat&logo=selenium">
<img alt="Issues" src="https://img.shields.io/badge/Tensorflow-informational?style=flat&logo=tensorflow">
<img alt="Issues" src="https://img.shields.io/badge/Powershell-informational?style=flat&logo=powershell">
<img alt="Issues" src="https://img.shields.io/badge/Firefox-informational?style=flat&logo=firefox">

</p>

The software category consists of a trilogy of modules - a Windows Security Event Log analyzer, a PE static analyzer, and automated RAM analysis. The solution will also contain a Graphical User Interface (GUI) to not only ease navigation and interaction between modules, but also to display the results in a concise manner for investigators to follow up. This GUI is designed for user-friendliness to ease the job of newer/less experienced investigators, while allowing the user to have a clear overview of their task-at-hand.<br>


## Software Requirements
* Python 3.8.6
* Mozilla FireFox


## Installation
### Local Approach
1. Ensure you have Mozila Firefox installed on your computer.
2. Ensure all dependencies are installed `pip install -r requirements.txt`

### Portable Approach
1. Install Portable FireFox into the project folder where installer is downloadable at: <br>
https://portableapps.com/apps/internet/firefox_portable
2. Browse to `\FirefoxPortable\Other\Source` and copy `FirefoxPortable.ini` o the \FirefoxPortable folder. 
3. Modify the FirefoxPortable.ini file you copied and modify the following values

| Keys | Values |
| - | - |
| DisableSplashScreen | true |
| AllowMultipleInstances | true |

4. Copy the whole project into a USB drive. 
5. Launch through `launch.bat` from your drive/disk

### Usage
User guide can be found [here](https://drive.google.com/file/d/1iqx-MvMHKhQXPNEukykN67jp3e6sqKKc/view?usp=sharing)

© 2021 Patrick Kang Wei Sheng & Kevin Tan All Rights Reserved
 <br>
