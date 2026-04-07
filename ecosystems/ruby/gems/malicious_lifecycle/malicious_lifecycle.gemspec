Gem::Specification.new do |s|
  s.name = "malicious_lifecycle"
  s.version = "0.0.1"
  s.summary = "local gem with native stub that runs during gem install"
  s.files = Dir["lib/**/*", "ext/**/*"]
  s.extensions = ["ext/mkrf_conf.rb"]
end
