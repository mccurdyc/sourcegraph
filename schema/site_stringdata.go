// Code generated by stringdata. DO NOT EDIT.

package schema

// SiteSchemaJSON is the content of the file "site.schema.json".
const SiteSchemaJSON = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "id": "https://sourcegraph.com/v1/site.schema.json#",
  "title": "Site configuration",
  "description": "Configuration for a Sourcegraph Server site.",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "auth.userOrgMap": {
      "description":
        "Ensure that matching users are members of the specified orgs (auto-joining users to the orgs if they are not already a member). Provide a JSON object of the form ` + "`" + `{\"*\": [\"org1\", \"org2\"]}` + "`" + `, where org1 and org2 are orgs that all users are automatically joined to. Currently the only supported key is ` + "`" + `\"*\"` + "`" + `.",
      "type": "object",
      "additionalProperties": {
        "type": "array",
        "items": {
          "type": "string"
        }
      }
    },
    "siteID": {
      "description":
        "The identifier for this site. A Sourcegraph site is a collection of one or more Sourcegraph Server instances that are all part of the same logical site. If the site ID is not set here, it is stored in the database the first time the server is run.",
      "type": "string"
    },
    "appURL": {
      "description": "Publicly accessible URL to web app (e.g., what you type into your browser).",
      "type": "string"
    },
    "disableTelemetry": {
      "description":
        "Prevent usage data from being sent back to Sourcegraph (no private code is sent and URLs are sanitized to prevent leakage of private data).",
      "type": "boolean"
    },
    "disableExampleSearches": {
      "description":
        "(Deprecated: use disableBuiltInSearches) Whether built-in searches should be hidden on the Searches page.",
      "type": "boolean"
    },
    "disableBuiltInSearches": {
      "description": "Whether built-in searches should be hidden on the Searches page.",
      "type": "boolean"
    },
    "tls.letsencrypt": {
      "description":
        "Toggles ACME functionality for automatically using a TLS certificate issued by the Let's Encrypt Certificate Authority.\nThe default value is auto, which uses the following conditions to switch on:\n - tlsCert and tlsKey are unset.\n - appURL is a https:// URL\n - Can successfully bind to port 443",
      "default": "auto",
      "enum": ["auto", "on", "off"],
      "type": "string"
    },
    "tlsCert": {
      "description": "TLS certificate for the web app.",
      "type": "string"
    },
    "tlsKey": {
      "description": "TLS key for the web app.",
      "type": "string"
    },
    "httpToHttpsRedirect": {
      "description": "Redirect users from HTTP to HTTPS.",
      "type": "boolean"
    },
    "corsOrigin": {
      "description": "Value for the Access-Control-Allow-Origin header returned with all requests.",
      "type": "string"
    },
    "disableBrowserExtension": {
      "type": "boolean",
      "default": false,
      "description": "Disable incoming connections from the Sourcegraph browser extension."
    },
    "autoRepoAdd": {
      "description": "Automatically add external public repositories on demand when visited.",
      "type": "boolean"
    },
    "disableAutoGitUpdates": {
      "description": "Disable periodically fetching git contents for existing repositories.",
      "type": "boolean",
      "default": false
    },
    "disablePublicRepoRedirects": {
      "description":
        "Disable redirects to sourcegraph.com when visiting public repositories that can't exist on this server.",
      "type": "boolean"
    },
    "phabricator": {
      "description":
        "JSON array of configuration for Phabricator hosts. See Phabricator Configuration section for more information.",
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "url": {
            "description": "URL of a Phabricator instance, such as https://phabricator.example.com",
            "type": "string"
          },
          "token": {
            "description": "API token for the Phabricator instance.",
            "type": "string"
          },
          "repos": {
            "description": "The list of repos available on Phabricator.",
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["path", "callsign"],
              "properties": {
                "path": {
                  "description": "Display path for the url e.g. gitolite/my/repo",
                  "type": "string"
                },
                "callsign": {
                  "description": "The unique Phabricator identifier for the repo, like 'MUX'.",
                  "type": "string"
                }
              }
            }
          }
        }
      }
    },
    "phabricatorURL": {
      "description": "(Deprecated: Use Phabricator) URL of Phabricator instance.",
      "type": "string"
    },
    "github": {
      "description":
        "JSON array of configuration for GitHub hosts. See GitHub Configuration section for more information.",
      "type": "array",
      "items": {
        "$ref": "#/definitions/GitHubConnection"
      }
    },
    "githubClientID": {
      "description": "Client ID for GitHub.",
      "type": "string"
    },
    "githubClientSecret": {
      "description": "Client secret for GitHub.",
      "type": "string"
    },
    "githubPersonalAccessToken": {
      "description": "(Deprecated: Use GitHub) Personal access token for GitHub. ",
      "type": "string"
    },
    "githubEnterpriseURL": {
      "description": "(Deprecated: Use GitHub) URL of GitHub Enterprise instance from which to sync repositories.",
      "type": "string"
    },
    "githubEnterpriseCert": {
      "description":
        "(Deprecated: Use GitHub) TLS certificate of GitHub Enterprise instance, if from a CA that's not part of the standard certificate chain.",
      "type": "string"
    },
    "githubEnterpriseAccessToken": {
      "description": "(Deprecated: Use GitHub) Access token to authenticate to GitHub Enterprise API.",
      "type": "string"
    },
    "gitlab": {
      "description": "JSON array of configuration for GitLab hosts.",
      "type": "array",
      "items": {
        "$ref": "#/definitions/GitLabConnection"
      }
    },
    "awsCodeCommit": {
      "description": "JSON array of configuration for AWS CodeCommit endpoints.",
      "type": "array",
      "items": {
        "$ref": "#/definitions/AWSCodeCommitConnection"
      }
    },
    "bitbucketServer": {
      "description": "JSON array of configuration for Bitbucket Server hosts.",
      "type": "array",
      "items": {
        "$ref": "#/definitions/BitbucketServerConnection"
      }
    },
    "gitoliteHosts": {
      "description": "Space separated list of mappings from repo name prefix to gitolite hosts.",
      "type": "string"
    },
    "gitoliteRepoBlacklist": {
      "description":
        "Regular expression to filter repos from auto-discovery, so they will not get cloned automatically.",
      "type": "string"
    },
    "gitMaxConcurrentClones": {
      "description": "Maximum number of git clone processes that will be run concurrently to update repositories.",
      "type": "integer",
      "default": 5
    },
    "gitOriginMap": {
      "description":
        "Space separated list of mappings from repo name prefix to origin url, for example \"github.com/!https://github.com/%.git\".",
      "type": "string"
    },
    "repos.list": {
      "description": "JSON array of configuration for external repositories.",
      "type": "array",
      "items": {
        "$ref": "#/definitions/Repository"
      }
    },
    "lightstepAccessToken": {
      "description": "Access token for sending traces to LightStep.",
      "type": "string"
    },
    "lightstepProject": {
      "description": "The project id on LightStep, only used for creating links to traces.",
      "type": "string"
    },
    "useJaeger": {
      "description":
        "Use local Jaeger instance for tracing. Data Center only.\n\nAfter enabling Jaeger and updating your Kubernetes cluster, ` + "`" + `kubectl get pods` + "`" + `\nshould display pods prefixed with ` + "`" + `jaeger-cassandra` + "`" + `,\n` + "`" + `jaeger-collector` + "`" + `, and ` + "`" + `jaeger-query` + "`" + `. ` + "`" + `jaeger-collector` + "`" + ` will start\ncrashing until you initialize the Cassandra DB. To do so, do the\nfollowing:\n\n1. Install [` + "`" + `cqlsh` + "`" + `](https://pypi.python.org/pypi/cqlsh).\n1. ` + "`" + `kubectl port-forward $(kubectl get pods | grep jaeger-cassandra | awk '{ print $1 }') 9042` + "`" + `\n1. ` + "`" + `git clone https://github.com/uber/jaeger && cd jaeger && MODE=test ./plugin/storage/cassandra/schema/create.sh | cqlsh` + "`" + `\n1. ` + "`" + `kubectl port-forward $(kubectl get pods | grep jaeger-query | awk '{ print $1 }') 16686` + "`" + `\n1. Go to http://localhost:16686 to view the Jaeger dashboard.",
      "type": "boolean"
    },
    "noGoGetDomains": {
      "description": "List of domains to NOT perform go get on. Separated by ','.",
      "type": "string"
    },
    "repoListUpdateInterval": {
      "description":
        "Interval (in minutes) for checking code hosts (such as GitHub, Gitolite, etc.) for new repositories.",
      "type": "integer",
      "default": 1
    },
    "ssoUserHeader": {
      "description":
        "Header injected by an SSO proxy to indicate the logged in user.\n\nDEPRECATED: Use auth.provider==\"http-header\" and auth.userIdentityHTTPHeader instead.",
      "type": "string"
    },
    "oidcProvider": {
      "description":
        "The URL of the OpenID Connect Provider\n\nDEPRECATED: Use auth.provider==\"openidconnect\" and auth.openidconnect's \"issuer\" property instead.",
      "type": "string"
    },
    "oidcClientID": {
      "description":
        "OIDC Client ID\n\nDEPRECATED: Use auth.provider==\"openidconnect\" and auth.openidconnect's \"clientID\" property instead.",
      "type": "string"
    },
    "oidcClientSecret": {
      "description":
        "OIDC Client Secret\n\nDEPRECATED: Use auth.provider==\"openidconnect\" and auth.openidconnect's \"clientSecret\" property instead.",
      "type": "string"
    },
    "oidcEmailDomain": {
      "description":
        "Whitelisted email domain for logins, e.g. 'mycompany.com'\n\nDEPRECATED: Use auth.provider==\"openidconnect\" and auth.openidconnect's \"requireEmailDomain\" property instead.",
      "type": "string"
    },
    "oidcOverrideToken": {
      "description":
        "Token to circumvent OIDC layer (testing only)\n\nDEPRECATED: Use auth.provider==\"openidconnect\" and auth.openidconnect's \"overrideToken\" property instead.",
      "type": "string"
    },
    "samlIDProviderMetadataURL": {
      "description":
        "SAML Identity Provider metadata URL (for dyanmic configuration of SAML Service Provider)\n\nDEPRECATED: Use auth.provider==\"saml\" and auth.saml's \"identityProviderMetadataURL\" property instead.",
      "type": "string"
    },
    "samlSPCert": {
      "description":
        "SAML Service Provider certificate\n\nDEPRECATED: Use auth.provider==\"saml\" and auth.saml's \"serviceProviderCertificate\" property instead.",
      "type": "string"
    },
    "samlSPKey": {
      "description":
        "SAML Service Provider private key\n\nDEPRECATED: Use auth.provider==\"saml\" and auth.saml's \"serviceProviderPrivateKey\" property instead.",
      "type": "string"
    },
    "searchScopes": {
      "description":
        "JSON array of custom search scopes (e.g., [{\"name\":\"Text Files\",\"value\":\"file:\\.txt$\"}]).\n\nDEPRECATED: Values should be moved to the \"settings\" field's \"search.scopes\" property.",
      "type": "array",
      "items": {
        "$ref": "settings.schema.json#/definitions/SearchScope"
      }
    },
    "htmlHeadTop": {
      "description": "HTML to inject at the top of the ` + "`" + `<head>` + "`" + ` element on each page, for analytics scripts",
      "type": "string"
    },
    "htmlHeadBottom": {
      "description": "HTML to inject at the bottom of the ` + "`" + `<head>` + "`" + ` element on each page, for analytics scripts",
      "type": "string"
    },
    "htmlBodyTop": {
      "description": "HTML to inject at the top of the ` + "`" + `<body>` + "`" + ` element on each page, for analytics scripts",
      "type": "string"
    },
    "htmlBodyBottom": {
      "description": "HTML to inject at the bottom of the ` + "`" + `<body>` + "`" + ` element on each page, for analytics scripts",
      "type": "string"
    },
    "licenseKey": {
      "description": "License key. You must purchase a license to obtain this.",
      "type": "string"
    },
    "maxReposToSearch": {
      "description":
        "The maximum number of repos to search across. The user is prompted to narrow their query if exceeded. The value -1 means unlimited.",
      "type": "integer",
      "default": 500
    },
    "adminUsernames": {
      "description":
        "Space-separated list of usernames that indicates which users will be treated as instance admins\n\nDEPRECATED: On new site installations, admins can designate other users as admins in the site admin area. That is the preferred way to designate admins. This configuration option will be removed in a future version. All users named in this configuration setting will be designated as admins, so if the server has been run with this option once, this setting can be safely removed without loss of admin access to the named users.",
      "type": "string"
    },
    "executeGradleOriginalRootPaths": {
      "description":
        "Java: A comma-delimited list of patterns that selects repository revisions for which to execute Gradle scripts, rather than extracting Gradle metadata statically. **Security note:** these should be restricted to repositories within your own organization. A percent sign ('%') can be used to prefix-match. For example, ` + "`" + `git://my.internal.host/org1/%,git://my.internal.host/org2/repoA?%` + "`" + ` would select all revisions of all repositories in org1 and all revisions of repoA in org2.",
      "type": "string"
    },
    "privateArtifactRepoID": {
      "description":
        "Java: Private artifact repository ID in your build files. If you do not explicitly include the private artifact repository, then set this to some unique string (e.g,. \"my-repository\").",
      "type": "string"
    },
    "privateArtifactRepoURL": {
      "description":
        "Java: The URL that corresponds to privateArtifactRepoID (e.g., http://my.artifactory.local/artifactory/root).",
      "type": "string"
    },
    "privateArtifactRepoUsername": {
      "description": "Java: The username to authenticate to the private Artifactory.",
      "type": "string"
    },
    "privateArtifactRepoPassword": {
      "description": "Java: The password to authenticate to the private Artifactory.",
      "type": "string"
    },
    "secretKey": {
      "description": "A secret key for this site, used for generating org invites.",
      "type": "string"
    },
    "auth.provider": {
      "description":
        "The authentication provider to use for identifying and signing in users. Defaults to built-in authentication.",
      "default": "builtin",
      "type": "string",
      "enum": ["builtin", "openidconnect", "saml", "http-header"]
    },
    "auth.allowSignup": {
      "description":
        "Allows new visitors to sign up for accounts. The sign-up page will be enabled and accessible to all visitors.\n\nSECURITY: If the site has no users (i.e., during initial setup), it will always allow the first user to sign up and become site admin **without any approval** (first user to sign up becomes the admin).\n\nRequires auth.provider == \"builtin\".",
      "type": "boolean",
      "default": false
    },
    "auth.public": {
      "description":
        "Allows anonymous visitors full read access to repositories, code files, search, and other data (except site configuration).\n\nSECURITY WARNING: If you enable this, you must ensure that only authorized users can access the server (using firewall rules or an external proxy, for example).\n\nRequires auth.provider == \"builtin\".",
      "type": "boolean",
      "default": false
    },
    "auth.openIDConnect": {
      "$ref": "#/definitions/OpenIDConnectAuthProvider"
    },
    "auth.saml": {
      "$ref": "#/definitions/SAMLAuthProvider"
    },
    "auth.userIdentityHTTPHeader": {
      "description":
        "The name (case-insensitive) of an HTTP header whose value is taken to be the username of the client requesting the page. Set this value when using an HTTP proxy that authenticates requests, and you don't want the extra configurability of the other authentication methods.\n\nRequires auth.provider==\"http-header\".",
      "type": "string"
    },
    "email.smtp": {
      "$ref": "#/definitions/SMTPServerConfig"
    },
    "email.address": {
      "description": "The \"from\" address for emails sent by this server.",
      "type": "string",
      "format": "email",
      "default": "noreply@sourcegraph.com"
    },
    "update.channel": {
      "description": "The channel on which to automatically check for Sourcegraph Server updates.",
      "type": ["string"],
      "enum": ["release", "none"],
      "default": "release"
    },
    "langservers": {
      "description": "Language server configuration.",
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "language": {
            "description": "Name of the language mode for the langserver (e.g. go, java)",
            "type": "string"
          },
          "address": {
            "description": "TCP address of the language server.",
            "type": "string",
            "pattern": "^tcp://",
            "format": "uri"
          }
        }
      }
    },
    "settings": {
      "description": "Site settings. Organization and user settings override site settings.",
      "$ref": "settings.schema.json#"
    }
  },
  "definitions": {
    "GitHubConnection": {
      "type": "object",
      "additionalProperties": false,
      "required": ["token"],
      "properties": {
        "url": {
          "description":
            "URL of a GitHub instance, such as https://github.com or https://github-enterprise.example.com",
          "type": "string",
          "pattern": "^https?://",
          "format": "uri"
        },
        "gitURLType": {
          "description":
            "The type of Git URLs to use for cloning and fetching Git repositories on this GitHub instance.\n\nIf \"http\", Sourcegraph will access GitLab repositories using Git URLs of the form http(s)://github.com/myteam/myproject.git (using https: if the GitHub instance uses HTTPS).\n\nIf \"ssh\", Sourcegraph will access GitHub repositories using Git URLs of the form git@github.com:myteam/myproject.git. See the documentation for how to provide SSH private keys and known_hosts: https://about.sourcegraph.com/docs/server/config/repositories#repositories-that-need-https-or-ssh-authentication.",
          "type": "string",
          "enum": ["http", "ssh"],
          "default": "http"
        },
        "token": {
          "description": "A GitHub personal access token with repo and org scope.",
          "type": "string",
          "pattern": "^[^<>]+$"
        },
        "certificate": {
          "description": "TLS certificate of a GitHub Enterprise instance.",
          "type": "string"
        },
        "repos": {
          "description":
            "An array of repository \"owner/name\" strings specifying which GitHub or GitHub Enterprise repositories to mirror on Sourcegraph Server.",
          "type": "array",
          "items": { "type": "string", "pattern": "^[\\w-]+/[\\w.-]+$" }
        },
        "repositoryQuery": {
          "description":
            "An array of strings specifying which GitHub or GitHub Enterprise repositories to mirror on Sourcegraph Server. The valid values are:\n\n- ` + "`" + `public` + "`" + ` mirrors all public repositories for GitHub Enterprise and is the equivalent of ` + "`" + `none` + "`" + ` for GitHub\n\n- ` + "`" + `affiliated` + "`" + ` mirrors all repositories affiliated with the configured token's user:\n\t- Private repositories with read access\n\t- Public repositories owned by the user or their orgs\n\t- Public repositories with write access\n\n- ` + "`" + `none` + "`" + ` mirrors no repositories (except those specified in the ` + "`" + `repos` + "`" + ` configuration property or added manually)\n\nIf multiple values are provided, their results are unioned.\n\nIf you need to narrow the set of mirrored repositories further (and don't want to enumerate the set in the \"repos\" configuration property), create a new bot/machine user on GitHub or GitHub Enterprise that is only affiliated with the desired repositories.",
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["public", "affiliated", "none"]
          },
          "default": ["public", "affiliated"]
        },
        "repositoryPathPattern": {
          "description":
            "The pattern used to generate a the corresponding Sourcegraph repository path for a GitHub or GitHub Enterprise repository. In the pattern, the variable \"{host}\" is replaced with the GitHub host (such as github.example.com), and \"{nameWithOwner}\" is replaced with the GitHub repository's \"owner/path\" (such as \"myorg/myrepo\").\n\nFor example, if your GitHub Enterprise URL is https://github.example.com and your Sourcegraph URL is https://src.example.com, then a repositoryPathPattern of \"{host}/{nameWithOwner}\" would mean that a GitHub repository at https://github.example.com/myorg/myrepo is available on Sourcegraph at https://src.example.com/github.example.com/myorg/myrepo.",
          "type": "string",
          "default": "{host}/{nameWithOwner}"
        },
        "initialRepositoryEnablement": {
          "description":
            "Defines whether repositories from this GitHub instance should be enabled and cloned when they are first seen by Sourcegraph. If false, the site admin must explicitly enable GitHub repositories (in the site admin area) to clone them and make them searchable on Sourcegraph. If true, they will be enabled and cloned immediately (subject to rate limiting by GitHub); site admins can still disable them explicitly, and they'll remain disabled.",
          "type": "boolean"
        },
        "preemptivelyClone": {
          "description":
            "Preemptively clone GitHub repositories added (instead of cloning on-demand when the repository is searched or viewed)\n\nDEPRECATED: Use initialRepositoryEnablement instead.",
          "type": "boolean"
        }
      }
    },
    "GitLabConnection": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url", "token"],
      "properties": {
        "url": {
          "description":
            "URL of a GitLab instance, such as https://gitlab.example.com or (for GitLab.com) https://gitlab.com",
          "type": "string",
          "default": "https://gitlab.com",
          "pattern": "^https?://",
          "not": {
            "type": "string",
            "pattern": "example\\.com"
          },
          "format": "uri"
        },
        "token": {
          "description": "A GitLab personal access token with \"api\" scope.",
          "type": "string",
          "pattern": "^[^<>]+$"
        },
        "gitURLType": {
          "description":
            "The type of Git URLs to use for cloning and fetching Git repositories on this GitLab instance.\n\nIf \"http\", Sourcegraph will access GitLab repositories using Git URLs of the form http(s)://gitlab.example.com/myteam/myproject.git (using https: if the GitLab instance uses HTTPS).\n\nIf \"ssh\", Sourcegraph will access GitLab repositories using Git URLs of the form git@example.gitlab.com:myteam/myproject.git. See the documentation for how to provide SSH private keys and known_hosts: https://about.sourcegraph.com/docs/server/config/repositories#repositories-that-need-https-or-ssh-authentication.",
          "type": "string",
          "enum": ["http", "ssh"],
          "default": "http"
        },
        "certificate": {
          "description": "TLS certificate of a GitLab instance.",
          "type": "string"
        },
        "projectQuery": {
          "description":
            "An array of strings specifying which GitLab projects to mirror on Sourcegraph Server. Each string is a URL query string for the GitLab projects API, such as \"?membership=true&search=foo\".\n\nThe query string is passed directly to GitLab to retrieve the list of projects. The special string \"none\" can be used as the only element to disable this feature. Projects matched by multiple query strings are only imported once. See https://docs.gitlab.com/ee/api/projects.html#list-all-projects for available query string options.",
          "type": "array",
          "default": ["?membership=true"],
          "items": {
            "type": "string"
          }
        },
        "repositoryPathPattern": {
          "description":
            "The pattern used to generate a the corresponding Sourcegraph repository path for a GitLab project. In the pattern, the variable \"{host}\" is replaced with the GitLab URL's host (such as gitlab.example.com), and \"{pathWithNamespace}\" is replaced with the GitLab project's \"namespace/path\" (such as \"myteam/myproject\").\n\nFor example, if your GitLab is https://gitlab.example.com and your Sourcegraph is https://src.example.com, then a repositoryPathPattern of \"{host}/{pathWithNamespace}\" would mean that a GitLab project at https://gitlab.example.com/myteam/myproject is available on Sourcegraph at https://src.example.com/gitlab.example.com/myteam/myproject.",
          "type": "string",
          "default": "{host}/{pathWithNamespace}"
        },
        "initialRepositoryEnablement": {
          "description":
            "Defines whether repositories from this GitLab instance should be enabled and cloned when they are first seen by Sourcegraph. If false, the site admin must explicitly enable GitLab repositories (in the site admin area) to clone them and make them searchable on Sourcegraph. If true, they will be enabled and cloned immediately (subject to rate limiting by GitLab); site admins can still disable them explicitly, and they'll remain disabled.",
          "type": "boolean"
        }
      }
    },
    "BitbucketServerConnection": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url", "token"],
      "properties": {
        "url": {
          "description": "URL of a Bitbucket Server instance, such as https://bitbucket.example.com",
          "type": "string",
          "pattern": "^https?://",
          "not": {
            "type": "string",
            "pattern": "example\\.com"
          },
          "format": "uri"
        },
        "token": {
          "description":
            "A Bitbucket Server personal access token with Read scope. Create one at https://[your-bitbucket-hostname]/plugins/servlet/access-tokens/add",
          "type": "string",
          "pattern": "^[^<>]+$"
        },
        "gitURLType": {
          "description":
            "The type of Git URLs to use for cloning and fetching Git repositories on this Bitbucket Server instance.\n\nIf \"http\", Sourcegraph will access Bitbucket Server repositories using Git URLs of the form http(s)://bitbucket.example.com/scm/myproject/myrepo.git (using https: if the Bitbucket Server instance uses HTTPS).\n\nIf \"ssh\", Sourcegraph will access Bitbucket Server repositories using Git URLs of the form ssh://git@example.bitbucket.com/myproject/myrepo.git. See the documentation for how to provide SSH private keys and known_hosts: https://about.sourcegraph.com/docs/server/config/repositories#repositories-that-need-https-or-ssh-authentication.",
          "type": "string",
          "enum": ["http", "ssh"],
          "default": "http"
        },
        "certificate": {
          "description": "TLS certificate of a Bitbucket Server instance.",
          "type": "string"
        },
        "repositoryPathPattern": {
          "description":
            "The pattern used to generate the corresponding Sourcegraph repository path for a Bitbucket Server repository.\n\n - \"{host}\" is replaced with the Bitbucket Server URL's host (such as bitbucket.example.com)\n - \"{projectKey}\" is replaced with the Bitbucket repository's parent project key (such as \"PRJ\")\n - \"{repositorySlug}\" is replaced with the Bitbucket repository's slug key (such as \"my-repo\").\n\nFor example, if your Bitbucket Server is https://bitbucket.example.com and your Sourcegraph is https://src.example.com, then a repositoryPathPattern of \"{host}/{projectKey}/{repositorySlug}\" would mean that a Bitbucket Server repository at https://bitbucket.example.com/projects/PRJ/repos/my-repo is available on Sourcegraph at https://src.example.com/bitbucket.example.com/PRJ/my-repo.",
          "type": "string",
          "default": "{host}/{projectKey}/{repositorySlug}"
        },
        "initialRepositoryEnablement": {
          "description":
            "Defines whether repositories from this Bitbucket Server instance should be enabled and cloned when they are first seen by Sourcegraph. If false, the site admin must explicitly enable Bitbucket Server repositories (in the site admin area) to clone them and make them searchable on Sourcegraph. If true, they will be enabled and cloned immediately (subject to rate limiting by Bitbucket Server); site admins can still disable them explicitly, and they'll remain disabled.",
          "type": "boolean"
        }
      }
    },
    "AWSCodeCommitConnection": {
      "type": "object",
      "additionalProperties": false,
      "required": ["region", "accessKeyID", "secretAccessKey"],
      "properties": {
        "region": {
          "description":
            "The AWS region in which to access AWS CodeCommit. See the list of supported regions at https://docs.aws.amazon.com/codecommit/latest/userguide/regions.html#regions-git.",
          "type": "string",
          "default": "us-east-1",
          "pattern": "^[a-z\\d-]+$",
          "enum": [
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ca-central-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "sa-east-1",
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2"
          ]
        },
        "accessKeyID": {
          "description":
            "The AWS access key ID to use when listing and updating repositories from AWS CodeCommit. Must have the AWSCodeCommitReadOnly IAM policy.",
          "type": "string"
        },
        "secretAccessKey": {
          "description": "The AWS secret access key (that corresponds to the AWS access key ID set in ` + "`" + `accessKeyID` + "`" + `).",
          "type": "string"
        },
        "repositoryPathPattern": {
          "description":
            "The pattern used to generate a the corresponding Sourcegraph repository path for an AWS CodeCommit repository. In the pattern, the variable \"{name}\" is replaced with the repository's name.\n\nFor example, if your Sourcegraph instance is at https://src.example.com, then a repositoryPathPattern of \"awsrepos/{name}\" would mean that a AWS CodeCommit repository named \"myrepo\" is available on Sourcegraph at https://src.example.com/awsrepos/myrepo.",
          "type": "string",
          "default": "{name}"
        },
        "initialRepositoryEnablement": {
          "description":
            "Defines whether repositories from AWS CodeCommit should be enabled and cloned when they are first seen by Sourcegraph. If false, the site admin must explicitly enable AWS CodeCommit repositories (in the site admin area) to clone them and make them searchable on Sourcegraph. If true, they will be enabled and cloned immediately (subject to rate limiting by AWS); site admins can still disable them explicitly, and they'll remain disabled.",
          "type": "boolean"
        }
      }
    },
    "Repository": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url", "path"],
      "properties": {
        "type": {
          "description": "Type of the version control system for this repository, such as \"git\"",
          "type": "string",
          "enum": ["git"],
          "default": "git"
        },
        "url": {
          "description": "Clone URL for the repository, such as git@example.com:my/repo.git",
          "type": "string"
        },
        "path": {
          "description": "Display path on Sourcegraph for the repository, such as my/repo",
          "type": "string",
          "pattern": "^[\\w_]"
        },
        "links": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "repository": {
              "description":
                "URL specifying where to view the repository at an external location e.g. \"https://example.com/myrepo\"",
              "type": "string"
            },
            "commit": {
              "description":
                "URL template for specifying how to link to commits at an external location. Use \"{commit}\" as a placeholder for a given commit ID e.g. \"https://example.com/myrepo/view-commit/{commit}\"",
              "type": "string"
            },
            "tree": {
              "description":
                "URL template for specifying how to link to paths at an external location. Use \"{path}\" as a placeholder for a given path and \"{rev}\" as a placeholder for a given revision e.g. \"https://example.com/myrepo@{rev}/browse/{path}\"",
              "type": "string"
            },
            "blob": {
              "description":
                "URL template for specifying how to link to files at an external location. Use \"{path}\" as a placeholder for a given path and \"{rev}\" as a placeholder for a given revision e.g. \"https://example.com/myrepo@{rev}/browse/{path}\"",
              "type": "string"
            }
          }
        }
      }
    },
    "OpenIDConnectAuthProvider": {
      "description": "Configures the OpenID Connect authentication provider for SSO.",
      "type": "object",
      "additionalProperties": false,
      "required": ["issuer", "clientID", "clientSecret"],
      "properties": {
        "issuer": {
          "description": "The URL of the OpenID Connect issuer.\n\nFor Google Apps: https://accounts.google.com",
          "type": "string",
          "format": "uri",
          "pattern": "^https?://"
        },
        "clientID": {
          "description":
            "The client ID for the OpenID Connect client for this site.\n\nFor Google Apps: obtain this value from the API console (https://console.developers.google.com), as described at https://developers.google.com/identity/protocols/OpenIDConnect#getcredentials",
          "type": "string",
          "pattern": "^[^<]"
        },
        "clientSecret": {
          "description":
            "The client secret for the OpenID Connect client for this site.\n\nFor Google Apps: obtain this value from the API console (https://console.developers.google.com), as described at https://developers.google.com/identity/protocols/OpenIDConnect#getcredentials",
          "type": "string",
          "pattern": "^[^<]"
        },
        "requireEmailDomain": {
          "description":
            "Only allow users to authenticate if their email domain is equal to this value (example: mycompany.com). Do not include a leading \"@\". If not set, all users on this OpenID Connect provider can authenticate to Sourcegraph.",
          "type": "string",
          "pattern": "^[^<@]"
        },
        "overrideToken": {
          "description":
            "(For testing and development only) A token used to circumvent the OpenID Connect authentication layer.",
          "type": "string"
        }
      }
    },
    "SAMLAuthProvider": {
      "description": "Configures the SAML authentication provider for SSO.",
      "type": "object",
      "additionalProperties": false,
      "required": ["serviceProviderCertificate", "serviceProviderPrivateKey"],
      "properties": {
        "identityProviderMetadataURL": {
          "description":
            "SAML Identity Provider metadata URL (for dynamic configuration of the SAML Service Provider).",
          "type": "string",
          "format": "uri",
          "pattern": "^https?://"
        },
        "identityProviderMetadata": {
          "description":
            "SAML Identity Provider metadata XML contents (for static configuration of the SAML Service Provider). The value of this field should be an XML document whose root element is ` + "`" + `<EntityDescriptor>` + "`" + `.",
          "type": "string"
        },
        "serviceProviderCertificate": {
          "description":
            "SAML Service Provider certificate in X.509 encoding (begins with \"-----BEGIN CERTIFICATE-----\").",
          "type": "string",
          "pattern": "^-----BEGIN CERTIFICATE-----\n"
        },
        "serviceProviderPrivateKey": {
          "description":
            "SAML Service Provider private key in PKCS#8 encoding (begins with \"-----BEGIN PRIVATE KEY-----\").",
          "type": "string",
          "pattern": "^-----BEGIN PRIVATE KEY-----\n"
        }
      }
    },
    "SMTPServerConfig": {
      "description":
        "The SMTP server used to send transactional emails (such as email verifications, reset-password emails, and notifications).",
      "type": "object",
      "additionalProperties": false,
      "required": ["host", "port", "authentication"],
      "properties": {
        "host": {
          "description": "The SMTP server host.",
          "type": "string"
        },
        "port": {
          "description": "The SMTP server port.",
          "type": "integer"
        },
        "username": {
          "description": "The username to use when communicating with the SMTP server.",
          "type": "string"
        },
        "password": {
          "description": "The username to use when communicating with the SMTP server.",
          "type": "string"
        },
        "authentication": {
          "description": "The type of authentication to use for the SMTP server.",
          "type": "string",
          "enum": ["none", "PLAIN", "CRAM-MD5"]
        },
        "domain": {
          "description": "The HELO domain to provide to the SMTP server (if needed).",
          "type": "string"
        }
      }
    }
  }
}
`
