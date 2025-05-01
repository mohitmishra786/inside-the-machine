---
layout: default
---

<div class="home-page">
  <section class="hero">
    <h1>{{ site.title }}</h1>
    <h2>{{ site.subtitle }}</h2>
    <p>{{ site.description }}</p>
    <div class="cta-buttons">
      <a href="{{ '/chapters' | relative_url }}" class="btn primary">Start Reading</a>
      <a href="{{ '/about' | relative_url }}" class="btn">About</a>
    </div>
  </section>
</div> 