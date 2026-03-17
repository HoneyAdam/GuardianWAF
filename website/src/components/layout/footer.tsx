import { Link } from 'react-router-dom'
import { Shield, Github } from 'lucide-react'

export function Footer() {
  return (
    <footer className="border-t border-border bg-background" role="contentinfo">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 py-12">
          <div className="md:col-span-1">
            <Link to="/" className="flex items-center gap-2 font-semibold text-foreground">
              <Shield className="h-5 w-5 text-accent" />
              <span>GuardianWAF</span>
            </Link>
            <p className="mt-3 text-sm text-muted leading-relaxed">
              Zero-dependency WAF.<br />
              One binary. Total protection.
            </p>
          </div>

          <div>
            <h4 className="text-sm font-semibold text-foreground mb-4">Product</h4>
            <ul className="space-y-2">
              <li><Link to="/#features" className="text-sm text-muted hover:text-foreground transition-colors">Features</Link></li>
              <li><Link to="/#architecture" className="text-sm text-muted hover:text-foreground transition-colors">Architecture</Link></li>
              <li><Link to="/#performance" className="text-sm text-muted hover:text-foreground transition-colors">Performance</Link></li>
              <li><Link to="/#comparison" className="text-sm text-muted hover:text-foreground transition-colors">Comparison</Link></li>
            </ul>
          </div>

          <div>
            <h4 className="text-sm font-semibold text-foreground mb-4">Documentation</h4>
            <ul className="space-y-2">
              <li><Link to="/docs#getting-started" className="text-sm text-muted hover:text-foreground transition-colors">Getting Started</Link></li>
              <li><Link to="/docs#configuration" className="text-sm text-muted hover:text-foreground transition-colors">Configuration</Link></li>
              <li><Link to="/docs#detection-engine" className="text-sm text-muted hover:text-foreground transition-colors">Detection Engine</Link></li>
              <li><Link to="/docs#api-reference" className="text-sm text-muted hover:text-foreground transition-colors">API Reference</Link></li>
            </ul>
          </div>

          <div>
            <h4 className="text-sm font-semibold text-foreground mb-4">Community</h4>
            <ul className="space-y-2">
              <li>
                <a
                  href="https://github.com/GuardianWAF/GuardianWAF"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-muted hover:text-foreground transition-colors inline-flex items-center gap-1.5"
                >
                  <Github className="h-3.5 w-3.5" />
                  GitHub
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/GuardianWAF/GuardianWAF/issues"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-muted hover:text-foreground transition-colors"
                >
                  Issues
                </a>
              </li>
              <li>
                <a
                  href="https://github.com/GuardianWAF/GuardianWAF/releases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-muted hover:text-foreground transition-colors"
                >
                  Releases
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t border-border py-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-muted">
            &copy; {new Date().getFullYear()} ECOSTACK TECHNOLOGY. All rights reserved.
          </p>
          <p className="text-xs text-muted">
            Released under the MIT License.
          </p>
        </div>
      </div>
    </footer>
  )
}
