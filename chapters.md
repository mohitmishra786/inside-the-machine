---
layout: default
title: Chapters
---

<div class="chapters-list">
  <h1>Table of Contents</h1>
  
  {% assign parts = site.chapters | group_by: "part" | sort: "name" %}
  {% for part in parts %}
    <h2 class="part-title">{{ part.name }}</h2>
    <ul>
      {% assign chapters = part.items | sort: "order" %}
      {% for chapter in chapters %}
        <li>
          <a href="{{ chapter.url | relative_url }}">{{ chapter.title }}</a>
          {% if chapter.status == "coming_soon" %}
            <span class="status coming-soon">Coming Soon</span>
          {% endif %}
        </li>
      {% endfor %}
    </ul>
  {% endfor %}
  
  {% if parts.size == 0 %}
    <div class="notice">
      <h3>Book in Progress</h3>
      <p>The book is currently being written and chapters will be added as they become available.</p>
      <p>Check back soon for updates or <a href="{{ '/about' | relative_url }}">subscribe to updates</a>.</p>
      
      <h3>Planned Chapters</h3>
      
      <h4 class="part-title">Part 1: Reverse Engineering Fundamentals</h4>
      <ul>
        <li>Chapter 1: Introduction to Reverse Engineering</li>
        <li>Chapter 2: Ethical Considerations in Reverse Engineering</li>
        <li>Chapter 3: Reverse Engineering Tools and Techniques</li>
      </ul>
      
      <h4 class="part-title">Part 2: Disassembly and Analysis</h4>
      <ul>
        <li>Chapter 4: Understanding Executable Formats</li>
        <li>Chapter 5: Assembly Language Basics</li>
        <li>Chapter 6: Static Code Analysis</li>
      </ul>
      
      <h4 class="part-title">Part 3: Dynamic Analysis and Debugging</h4>
      <ul>
        <li>Chapter 7: Dynamic Instrumentation</li>
        <li>Chapter 8: Debugging Techniques</li>
        <li>Chapter 9: Reverse Engineering Memory Structures</li>
      </ul>
      
      <h4 class="part-title">Part 4: Advanced Reverse Engineering</h4>
      <ul>
        <li>Chapter 10: Unpacking and Anti-Reversing Techniques</li>
        <li>Chapter 11: Hardware-Assisted Reverse Engineering</li>
        <li>Chapter 12: Reverse Engineering Embedded Systems</li>
      </ul>
      
      <h4 class="part-title">Part 5: Practical Applications</h4>
      <ul>
        <li>Chapter 13: Reverse Engineering for Security</li>
        <li>Chapter 14: Reverse Engineering for Software Maintenance</li>
        <li>Chapter 15: Reverse Engineering for Malware Analysis</li>
      </ul>
      
      <h4 class="part-title">Part 6: Future of Reverse Engineering</h4>
      <ul>
        <li>Chapter 16: Emerging Trends and Technologies</li>
        <li>Chapter 17: Conclusion: The Path Forward in Reverse Engineering</li>
      </ul>
    </div>
  {% endif %}
</div>
<style>
  .status {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    margin-left: 8px;
  }
  
  .coming-soon {
    background-color: var(--color-button-secondary-bg);
    color: var(--color-text-secondary);
  }
  
  .notice {
    padding: 20px;
    border: 1px solid var(--color-border);
    border-radius: 8px;
    margin: 20px 0;
  }
  
  .notice h3 {
    margin-top: 0;
  }
  
  .notice h4 {
    margin-bottom: 0.5rem;
  }
</style>