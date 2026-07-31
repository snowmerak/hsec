<script lang="ts">
  let {name, size = 20}: {name: string; size?: number} = $props();
</script>

<svg
  class="icon"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.8"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  {#if name === 'plus'}
    <path d="M12 5v14M5 12h14"/>
  {:else if name === 'lock'}
    <rect x="5" y="10" width="14" height="11" rx="2"/>
    <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>
  {:else if name === 'key'}
    <circle cx="8.5" cy="15.5" r="4.5"/>
    <path d="m12 12 7-7m-3 3 2 2m-5 1 2 2"/>
  {:else if name === 'save'}
    <path d="M5 4h12l2 2v14H5zM8 4v6h8V4M8 20v-6h8v6"/>
  {:else if name === 'trash'}
    <path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 11v5M14 11v5"/>
  {:else if name === 'eye'}
    <path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6"/>
    <circle cx="12" cy="12" r="2.5"/>
  {:else if name === 'eye-off'}
    <path d="m3 3 18 18M10.6 6.2A9 9 0 0 1 12 6c6 0 9.5 6 9.5 6a15 15 0 0 1-2.1 2.8M6.1 6.1C3.7 7.8 2.5 12 2.5 12s3.5 6 9.5 6a9 9 0 0 0 3-.5M9.9 9.9a3 3 0 0 0 4.2 4.2"/>
  {:else if name === 'copy'}
    <rect x="8" y="8" width="11" height="11" rx="2"/>
    <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>
  {:else if name === 'shield'}
    <path d="M12 3 5 6v5c0 4.6 2.8 8.1 7 10 4.2-1.9 7-5.4 7-10V6z"/>
    <path d="m9.5 12 1.7 1.7 3.6-3.8"/>
  {:else if name === 'info'}
    <circle cx="12" cy="12" r="9"/>
    <path d="M12 11v5M12 8h.01"/>
  {:else if name === 'check'}
    <path d="m5 12 4 4L19 6"/>
  {:else if name === 'alert'}
    <path d="M12 4 3.5 19h17zM12 9v4M12 16h.01"/>
  {:else if name === 'folder'}
    <path d="M3 6.5h6l2 2h10v9.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
  {:else if name === 'folder-plus'}
    <path d="M3 6.5h6l2 2h10v9.5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM12 12v5M9.5 14.5h5"/>
  {:else if name === 'usb'}
    <path d="M12 3v12M12 3l-2.5 2.5M12 3l2.5 2.5M12 9h4l2 2v2M12 12H8l-2 2v2"/>
    <circle cx="6" cy="18" r="2"/>
    <rect x="16.5" y="13" width="3" height="3" rx=".5"/>
    <circle cx="12" cy="18" r="2"/>
  {:else if name === 'refresh'}
    <path d="M20 7v5h-5M4 17v-5h5M6.1 8.5A7 7 0 0 1 18.6 7L20 12M4 12l1.4 5A7 7 0 0 0 17.9 15.5"/>
  {:else if name === 'chevron-right'}
    <path d="m9 5 7 7-7 7"/>
  {:else if name === 'chevron-left'}
    <path d="m15 5-7 7 7 7"/>
  {:else}
    <circle cx="12" cy="12" r="9"/>
  {/if}
</svg>
