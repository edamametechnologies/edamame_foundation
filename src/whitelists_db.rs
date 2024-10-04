// Built in default whitelists db
pub static WHITELISTS: &str = r#"{
  "date": "October 04th 2024",
  "whitelists": [
    {
      "name": "base_whitelist",
      "extends": "none",
      "endpoints": [
        {
          "destination": "api.edamame.tech",
          "port": 443,
          "description": "Edamame API endpoint"
        }
      ]
    },
    {
      "name": "cicd_dependencies",
      "extends": "base_whitelist",
      "endpoints": [
        {
          "destination": "github.com",
          "port": 443,
          "description": "GitHub main website"
        },
        {
          "destination": "api.github.com",
          "port": 443,
          "description": "GitHub API endpoint"
        },
        {
          "destination": "proxy.github.com",
          "port": 443,
          "description": "GitHub proxy server"
        },
        {
          "destination": "raw.githubusercontent.com",
          "port": 443,
          "description": "GitHub raw content"
        },
        {
          "destination": "objects.githubusercontent.com",
          "port": 443,
          "description": "GitHub object storage"
        },
        {
          "destination": "proxy.golang.org",
          "port": 443,
          "description": "Go module proxy"
        },
        {
          "destination": "registry.npmjs.org",
          "port": 443,
          "description": "npm package registry"
        },
        {
          "destination": "registry.yarnpkg.com",
          "port": 443,
          "description": "Yarn package registry"
        },
        {
          "destination": "pypi.org",
          "port": 443,
          "description": "Python Package Index"
        },
        {
          "destination": "files.pythonhosted.org",
          "port": 443,
          "description": "Python package files"
        },
        {
          "destination": "repo.maven.apache.org",
          "port": 443,
          "description": "Maven Central Repository"
        },
        {
          "destination": "services.gradle.org",
          "port": 443,
          "description": "Gradle services"
        },
        {
          "destination": "api.nuget.org",
          "port": 443,
          "description": "NuGet API"
        },
        {
          "destination": "rubygems.org",
          "port": 443,
          "description": "RubyGems package registry"
        },
        {
          "destination": "registry.hub.docker.com",
          "port": 443,
          "description": "Docker Hub registry"
        },
        {
          "destination": "quay.io",
          "port": 443,
          "description": "Quay container registry"
        },
        {
          "destination": "dart.dev",
          "port": 443,
          "description": "Dart programming language site"
        },
        {
          "destination": "pub.dev",
          "port": 443,
          "description": "Dart and Flutter package repository"
        },
        {
          "destination": "crates.io",
          "port": 443,
          "description": "Rust package registry"
        },
        {
          "destination": "static.rust-lang.org",
          "port": 443,
          "description": "Rust static resources"
        },
        {
          "destination": "golang.org",
          "port": 443,
          "description": "Go programming language site"
        },
        {
          "destination": "pkg.go.dev",
          "port": 443,
          "description": "Go package documentation"
        }
      ]
    },
    {
      "name": "cicd_tools",
      "extends": "none",
      "endpoints": [
        {
          "destination": "jenkins.io",
          "port": 443,
          "description": "Jenkins CI/CD"
        },
        {
          "destination": "circleci.com",
          "port": 443,
          "description": "CircleCI"
        },
        {
          "destination": "api.travis-ci.com",
          "port": 443,
          "description": "Travis CI API"
        },
        {
          "destination": "gitlab.com",
          "port": 443,
          "description": "GitLab"
        },
        {
          "destination": "atlassian.com",
          "port": 443,
          "description": "Atlassian (Jira, Confluence, Bitbucket)"
        },
        {
          "destination": "registry.terraform.io",
          "port": 443,
          "description": "Terraform registry"
        },
        {
          "destination": "galaxy.ansible.com",
          "port": 443,
          "description": "Ansible Galaxy"
        },
        {
          "destination": "api.chef.io",
          "port": 443,
          "description": "Chef API"
        },
        {
          "destination": "puppet.com",
          "port": 443,
          "description": "Puppet"
        },
        {
          "destination": "sonarqube.org",
          "port": 443,
          "description": "SonarQube"
        },
        {
          "destination": "snyk.io",
          "port": 443,
          "description": "Snyk security platform"
        },
        {
          "destination": "sentry.io",
          "port": 443,
          "description": "Sentry error tracking"
        },
        {
          "destination": "newrelic.com",
          "port": 443,
          "description": "New Relic monitoring"
        },
        {
          "destination": "api.datadoghq.com",
          "port": 443,
          "description": "Datadog API"
        },
        {
          "destination": "cmake.org",
          "port": 443,
          "description": "CMake build system"
        },
        {
          "destination": "bazel.build",
          "port": 443,
          "description": "Bazel build system"
        },
        {
          "destination": "apache.org",
          "port": 443,
          "description": "Apache Software Foundation"
        },
        {
          "destination": "visualstudio.com",
          "port": 443,
          "description": "Visual Studio services"
        },
        {
          "destination": "jetbrains.com",
          "port": 443,
          "description": "JetBrains tools"
        },
        {
          "destination": "codecov.io",
          "port": 443,
          "description": "Codecov code coverage"
        },
        {
          "destination": "coveralls.io",
          "port": 443,
          "description": "Coveralls code coverage"
        },
        {
          "destination": "selenium.dev",
          "port": 443,
          "description": "Selenium automation tool"
        },
        {
          "destination": "ci.appveyor.com",
          "port": 443,
          "description": "AppVeyor CI"
        },
        {
          "destination": "codeclimate.com",
          "port": 443,
          "description": "Code Climate quality platform"
        },
        {
          "destination": "brew.sh",
          "port": 443,
          "description": "Homebrew package manager"
        },
        {
          "destination": "packages.debian.org",
          "port": 443,
          "description": "Debian package repository"
        },
        {
          "destination": "packages.ubuntu.com",
          "port": 443,
          "description": "Ubuntu package repository"
        },
        {
          "destination": "fedoraproject.org",
          "port": 443,
          "description": "Fedora Project"
        },
        {
          "destination": "centos.org",
          "port": 443,
          "description": "CentOS Project"
        },
        {
          "destination": "alpinelinux.org",
          "port": 443,
          "description": "Alpine Linux"
        },
        {
          "destination": "archlinux.org",
          "port": 443,
          "description": "Arch Linux"
        }
      ]
    },
    {
      "name": "cicd",
      "extends": [
        "cicd_dependencies",
        "cicd_tools"
      ],
      "endpoints": []
    }
  ],
  "signature": "99ada0f91fb2df3694cb8feba3cbe31ccafa76ce2dba78b00f01986bda02cf14"
}"#;
