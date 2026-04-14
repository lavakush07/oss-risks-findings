module example.com/oss-risks-findings/golang

go 1.21

require github.com/gin-gonic/gin v1.6.3

require github.com/paysuper/paysuper-reporter v1.4.2

require github.com/zerobounty/tile38-client v0.10.2

// Typosquatting: misspelled package name (VulnCheck: squatted_package)
require github.com/aboringcompany/boringssl v0.0.0-20190101000000-000000000000
