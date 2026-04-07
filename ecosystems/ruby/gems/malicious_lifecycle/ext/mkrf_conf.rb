# frozen_string_literal: true

File.open(File.join(__dir__, "Makefile"), "w") do |f|
  f.puts "all: install"
  f.puts "install:"
  f.puts "\t@echo [oss-risks-findings] gem native extension install step ran"
end
