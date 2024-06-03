<script>
  import '../app.css';
</script>

<div class="flex h-16 bg-indigo-500 justify-center mb-4">
    <nav class="flex container px-4 gap-4">
        <a
            href="/"
            class="flex items-center text-white p-2"
        >
            Dashboard
        </a>

        <a
            href="/users"
            class="flex items-center text-white p-2"
        >
            Users
        </a>

        <a
            href="/settings"
            class="flex items-center text-white p-2"
        >
            Settings
        </a>
    </nav>
</div>

<slot />

<footer>
</footer>
