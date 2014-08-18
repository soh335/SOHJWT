Pod::Spec.new do |s|

  s.name         = "SOHJWT"
  s.version      = "0.0.1"
  s.summary      = "JWT encoder/decoder"

  s.description  = <<-DESC
                   simple JWT (json web token) encoder/decoder
                   DESC

  s.homepage     = "http://github.com/soh335/SOHJWT"
  s.license      = "MIT"
  s.author       = { "soh335" => "sugarbabe335@gmail.com" }

  s.ios.deployment_target = "7.0"
  s.osx.deployment_target = "10.9"

  s.source       = { :git => "https://github.com/soh335/SOHJWT.git", :tag => "0.0.1" }
  s.source_files  = "SOHJWT", "SOHJWT/**/*.{h,m}"
  s.requires_arc = true

end
