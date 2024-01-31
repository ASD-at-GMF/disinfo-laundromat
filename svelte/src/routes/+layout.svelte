<script>
	import '../app.pcss';
	import Header from '$components/Header.svelte';
	import Footer from '$components/Footer.svelte';
</script>

<div class="w-full min-h-screen bg-red-500 px-3 md:px-16 flex flex-col">
	<Header />
	<slot />
	<Footer className="mt-auto"/>
</div>
