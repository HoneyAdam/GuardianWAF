import { type DocContent, type DocBlock } from '@/content/docs'
import { CodeBlock } from '@/components/ui/code-block'
import { cn } from '@/lib/utils'
import { Info, AlertTriangle, Lightbulb } from 'lucide-react'

interface DocsContentProps {
  content: DocContent
}

function renderBlock(block: DocBlock, index: number) {
  switch (block.type) {
    case 'paragraph':
      return (
        <p key={index} className="text-muted leading-relaxed mb-4">
          {block.text}
        </p>
      )

    case 'heading': {
      const Tag = `h${block.level}` as 'h2' | 'h3' | 'h4'
      const sizes = {
        2: 'text-2xl font-bold mt-10 mb-4',
        3: 'text-xl font-semibold mt-8 mb-3',
        4: 'text-lg font-medium mt-6 mb-2',
      }
      return (
        <Tag
          key={index}
          id={block.id}
          className={cn('text-foreground scroll-mt-20', sizes[block.level])}
        >
          {block.text}
        </Tag>
      )
    }

    case 'code':
      return (
        <div key={index} className="mb-4">
          <CodeBlock
            code={block.code}
            language={block.language}
            filename={block.filename}
            showLineNumbers={block.code.split('\n').length > 5}
          />
        </div>
      )

    case 'list':
      if (block.ordered) {
        return (
          <ol key={index} className="list-decimal list-inside space-y-1.5 mb-4 text-muted">
            {block.items.map((item, i) => (
              <li key={i} className="leading-relaxed">{item}</li>
            ))}
          </ol>
        )
      }
      return (
        <ul key={index} className="list-disc list-inside space-y-1.5 mb-4 text-muted">
          {block.items.map((item, i) => (
            <li key={i} className="leading-relaxed">{item}</li>
          ))}
        </ul>
      )

    case 'table':
      return (
        <div key={index} className="overflow-x-auto mb-4 rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-card">
                {block.headers.map((h, i) => (
                  <th key={i} className="text-left px-4 py-2.5 font-medium text-foreground">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, ri) => (
                <tr key={ri} className="border-b border-border last:border-0">
                  {row.map((cell, ci) => (
                    <td key={ci} className="px-4 py-2.5 text-muted">
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )

    case 'callout': {
      const variants = {
        info: {
          icon: Info,
          bg: 'bg-accent/5 border-accent/20',
          iconColor: 'text-accent',
        },
        warning: {
          icon: AlertTriangle,
          bg: 'bg-warning/5 border-warning/20',
          iconColor: 'text-warning',
        },
        tip: {
          icon: Lightbulb,
          bg: 'bg-success/5 border-success/20',
          iconColor: 'text-success',
        },
      }
      const v = variants[block.variant]
      const Icon = v.icon
      return (
        <div key={index} className={cn('flex gap-3 p-4 rounded-lg border mb-4', v.bg)}>
          <Icon className={cn('h-5 w-5 shrink-0 mt-0.5', v.iconColor)} />
          <p className="text-sm text-muted leading-relaxed">{block.text}</p>
        </div>
      )
    }
  }
}

export function DocsContent({ content }: DocsContentProps) {
  return (
    <article className="min-w-0">
      <h1
        id={content.id}
        className="text-3xl font-bold text-foreground mb-6 scroll-mt-20"
      >
        {content.title}
      </h1>
      {content.content.map((block, i) => renderBlock(block, i))}
    </article>
  )
}
