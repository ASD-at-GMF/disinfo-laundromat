<script>
	import '../app.pcss';
	import Header from '$components/Header.svelte';
	import Footer from '$components/Footer.svelte';
</script>

<div class="flex min-h-screen w-full flex-col bg-red-500 px-3 md:px-16">
	<Header />
	<slot />
	<Footer class="mt-auto" />
</div>
