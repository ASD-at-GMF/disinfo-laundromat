<script lang="ts">
	import { cn } from '$utils';
	export let className: string | undefined = undefined;
</script>

<footer class={cn('w-100 h-2 bg-purple-500', className)}>
	<slot />
</footer>
