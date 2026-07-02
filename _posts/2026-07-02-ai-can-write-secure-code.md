---
layout: post
title: "AI can write secure code. Here's why it often doesn't."
date: 2026-07-02
author: Alex Bourla
description: "AI can write secure code, so why does so much AI-assisted development ship critical vulnerabilities? The problem isn't the models, it's incomplete requirements."
tags: [AI Security, Secure by Design, Vibe Coding, Threat Modelling, Shift Left, Application Security, Secure Development, LLM Security, AI-Assisted Development, Security Requirements]
permalink: /blog/ai-can-write-secure-code/
keywords: "AI secure code, AI-assisted development security, vibe coding security, secure by design, threat modelling, shift left, security requirements, LLM code security, application security"
---

Whatever you call it, AI-assisted development, vibe coding or just pair programming with your favourite coworker Claude, it's clear the landscape is changing. AI has enabled software to be built faster than ever before, but I think we've also created a fundamental problem.

Over the past few months I've come across several applications in both my professional and personal life that were clearly built rapidly with AI. They looked polished, worked well, and solved genuine business problems. Yet hidden beneath the surface were critical security vulnerabilities that could expose every customer's data.

So why did this happen? Was it that the AI models being used simply weren't good enough?

I decided to test that theory on my latest pet project, [FerryAlert.com](https://ferryalert.com) - a website intended to help people spot cancellations on ferry routes that regularly sell out, particularly for campervans and other large vehicles.

I deliberately leaned heavily on AI throughout the development process. I gave it the product idea, described the precise architecture I wanted, provided a detailed API specification, and then let it do much of the heavy lifting.

The result was genuinely impressive. Within a fraction of the time and cost of traditional development, I had a polished application that did almost everything I'd envisioned and looked better than my rusty CSS skills could achieve.

Then I started reviewing the security…

Even for a relatively simple application, I uncovered multiple critical or high severity vulnerabilities, including authorisation bypasses, weak authentication flows and poor session management. The volume of issues was significantly higher than I'd typically expect to find during a security assessment of an application of this size.

What surprised me wasn't that the AI made mistakes, it was the nature of those mistakes.

Every issue I found could ultimately be traced back to the same thing: I'd never explicitly told the AI what the security requirements were.

The models clearly understand security concepts and theory. The problem is that they're incredibly eager to satisfy the prompt you've given them. If your prompt focuses on functionality, they'll doggedly optimise for functionality. They won't reliably invent security requirements that you never asked for, even if they seem rather obvious to the humans designing the system in the first place.

For example, I saw cases where the model failed to assume that only administrators should be able to call administrative APIs, or that users shouldn't be able to assign themselves elevated roles during registration.

I suspect what I've seen is only the tip of the iceberg. AI is enabling people to build genuinely useful products at incredible speed, but many of those products may be carrying serious security debt from day one. I recently reported a NoSQL injection vulnerability to the founder of a rapidly growing one-person start-up that would have allowed unrestricted access to all of their users' personal data. His response stuck with me:

> "That's what AI gets you…"

Personally, I don't think that's what AI gets you. I think that's what incomplete requirements get you.

The good news is that I don't think the answer is to use less AI. It's to give it better requirements. Security requirements deserve the same level of thought and detail as functional ones.

In practice, many of those requirements can simply be written down as natural language guidance and kept alongside the project, whether that's in a `CLAUDE.md` file, Cursor rules, or whichever equivalent your AI tooling supports. Simple instructions such as "the API is the security boundary, not the UI" or "always prove the caller is authorised before returning or modifying data" go a surprisingly long way towards steering the model towards more secure implementations.

Security design reviews and threat modelling remain incredibly useful tools because they force us to think explicitly about trust boundaries, abuse cases and other security considerations before any code is written. Based on my experience, that's arguably even more important with AI, because we can't rely on it to infer security requirements in the same way an experienced engineer may. If the outputs of that process are fed into the AI alongside the functional requirements, today's models are definitely capable of producing much more secure code.

It's also where I think security practices need to change, and the idea of "shifting left" becomes more important than ever. Rather than reviewing AI-generated code after it's been written, or testing applications once they're deployed, we need to influence the requirements before the AI writes a single line of code. Getting those requirements right upfront is far more effective than trying to find vulnerabilities afterwards.

These days I work independently, helping organisations with everything from security strategy and architecture through to hands-on security engineering. My aim is simple: helping teams build systems that are secure by design, so security becomes an enabler rather than a bottleneck. If that sounds useful, [let's chat](/#contact).

P.S. Claude and I did eventually fix all of the security bugs and added additional guardrails to encourage secure-by-design code patterns going forwards. So if you ever find yourself struggling to fit your campervan, caravan or motorhome onto the Portsmouth–Bilbao ferry, do consider giving [FerryAlert](https://ferryalert.com) a try!
