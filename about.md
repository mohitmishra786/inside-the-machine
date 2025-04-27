---
layout: default
title: About the Book
---

<div class="about-page">
  <h1>About the Book</h1>  
  <div class="book-status">
    <h2>Book Status</h2>
    {% assign total_chapters = 17 %}
    {% assign completed_chapters = site.chapters | size %}
    {% assign progress_percent = completed_chapters | times: 100 | divided_by: total_chapters %}
    
    <div class="progress-bar-container">
      <div class="progress-bar" style="width: {{ progress_percent }}%;"></div>
    </div>
    <p class="progress-text">{{ completed_chapters }} of {{ total_chapters }} chapters available ({{ progress_percent }}% complete)</p>
    
    <p>This book is being written and published incrementally. Currently, we have sample chapters available, with more chapters being added regularly. The complete book will contain 17 chapters across 6 parts, covering the entire spectrum of reverse engineering from fundamentals to advanced techniques.</p>
    
    <p>You can subscribe to updates by watching the <a href="https://github.com/mohitmishra786/inside-the-machine" target="_blank">GitHub repository</a>. Each new chapter will be announced through GitHub releases.</p>
    
    <h3>Estimated Completion Timeline</h3>
    <p>The book is expected to be completed by the end of 2024, with new chapters released monthly. Check the <a href="https://github.com/mohitmishra786/inside-the-machine/blob/main/CHANGELOG.md" target="_blank">CHANGELOG</a> for the most recent updates.</p>
  </div>  
  <h2>Who This Book Is For</h2>
  <p>When software professionals encounter complex problems, they often face contradictions and struggle to find solutions. To overcome these challenges, it's crucial to view tough problems as opportunities for significant rewards. Embracing difficult challenges can lead to valuable insights and breakthroughs.</p>
  
  <p>With years of experience in reverse engineering, most challenging problems in software can be solved through systematic logical analysis. This book uses reverse engineering as a lens to explore problem analysis and resolution strategies. Readers will gain a deeper appreciation for logical reasoning, data structures, algorithms, and more through practical examples and insightful discussions.</p>
  
  <h2>Focus of the Book</h2>
  <p>This book serves as a comprehensive guide to the art of reverse engineering. It explores various techniques and strategies to extract valuable insights from software systems, with the goal of enhancing understanding, improving software quality, and addressing complex challenges.</p>
  
  <h2>Target Audience</h2>
  <ul>
    <li><strong>Software Developers</strong>: Individuals interested in understanding the inner workings of software systems.</li>
    <li><strong>Security Researchers</strong>: Professionals focused on analyzing software for security vulnerabilities.</li>
    <li><strong>Malware Analysts</strong>: Researchers investigating and reverse-engineering malicious software.</li>
    <li><strong>Software Architects</strong>: Those designing and maintaining large-scale software systems.</li>
    <li><strong>Embedded Systems Engineers</strong>: Developers working with complex hardware and firmware.</li>
    <li><strong>Computer Science Students</strong>: Learners aiming to strengthen their reverse engineering skills.</li>
    <li><strong>Hobbyists and Tinkerers</strong>: Curious individuals exploring the world of software internals.</li>
  </ul>
  
  <h2>About the Author</h2>
  <p>Mohit Mishra is a software engineer with experience in reverse engineering. With a passion for understanding how systems work at their core, he has spent years exploring the inner workings of software and hardware.</p>
  
  <h2>How to Contact</h2>
  <p>For additional information, updates, or support related to this book, please visit the webpage (hosted via GitHub Pages).</p>
  
  <p>Email <a href="mailto:immadmohit@gmail.com">immadmohit@gmail.com</a> to comment or ask technical questions about this book.</p>
  
  <h2>License</h2>
  <p>This repository is licensed under the MIT License - see the <a href="https://github.com/mohitmishra786/inside-the-machine/blob/main/LICENSE">LICENSE</a> file for details.</p>
  
  <h2>Copyright</h2>
  <p>Copyright ©chessMan786 2024. All rights reserved.</p>
</div>