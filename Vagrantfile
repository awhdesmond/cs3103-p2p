# -*- mode: ruby -*-
# vi: set ft=ruby :


Vagrant.configure("2") do |config|

  config.vm.define :dns do |dns|
    dns.vm.box = "ubuntu/xenial64"
    dns.vm.network "private_network", ip: "192.168.1.170"
    dns.vm.hostname = "dns"
  end

  config.vm.define :alpha do |alpha|
    alpha.vm.box = "ubuntu/xenial64"
    alpha.vm.network "private_network", ip: "192.168.1.171"
    alpha.vm.hostname = "alpha"
  end

  config.vm.define :beta do |beta|
    beta.vm.box = "ubuntu/xenial64"
    beta.vm.network "private_network", ip: "192.168.1.172"
    beta.vm.hostname = "beta"
  end

  config.vm.define :charlie do |charlie|
    charlie.vm.box = "ubuntu/xenial64"
    charlie.vm.network "private_network", ip: "192.168.1.173"
    charlie.vm.hostname = "charlie"
  end

  config.vm.define :delta do |delta|
    delta.vm.box = "ubuntu/xenial64"
    delta.vm.network "private_network", ip: "192.168.1.174"
    delta.vm.hostname = "delta"
  end

  config.vm.define :echo do |echo|
    echo.vm.box = "ubuntu/xenial64"
    echo.vm.network "private_network", ip: "192.168.1.175"
    echo.vm.hostname = "echo"
  end

end


