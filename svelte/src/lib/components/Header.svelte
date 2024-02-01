<script lang="ts">
	import { APP_TITLE } from '$config';
	import { cn } from '$utils';
	let className: string | undefined = undefined;
	export { className as class };
</script>

<header class={cn('w-100 flex justify-between py-1', className)}>
	<h1><a href="/">{APP_TITLE}</a></h1>
	<nav>
		<ul class="flex list-none">
			<li><a href="/search">Search</a></li>
			<li><a href=".">About</a></li>
			<li><a href=".">login</a></li>
			<ul></ul>
		</ul>
	</nav>
</header>
