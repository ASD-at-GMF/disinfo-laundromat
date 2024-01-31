<script lang="ts">
	import TabsRoot from '$components/TabsRoot.svelte';
	import TabsList from '$components/TabsList.svelte';
	import TabsTrigger from '$components/TabsTrigger.svelte';
	import TabsContent from '$components/TabsContent.svelte';
	import { Label, Button } from 'bits-ui';
</script>

<main class="w-100 ">
	<div class="grid grid-rows-2 gap-4">
		<section name="search" class="grid grid-cols-1 md:grid-cols-2 gap-4">
			<div class="bg-blue-300">random</div>
			<div class="h-[300px]">
				<TabsRoot value="content similarity">
					<TabsList>
						<TabsTrigger value="content similarity">Content similarity</TabsTrigger>
						<TabsTrigger value="metadata similarity">Metadata similarity</TabsTrigger>
					</TabsList>
					<TabsContent value="content similarity">test test 1</TabsContent>
					<TabsContent value="metadata similarity">test 2 test 2</TabsContent>
				</TabsRoot>
			</div>
		</section>
		<section name="use cases" class="grid grid-cols-1 md:grid-cols-3 gap-x-4">
			<div class="md:col-span-3 bg-green-300"> Label! </div>
			<div class="bg-pink-500">test1</div>
			<div class="bg-pink-500">test2</div>
			<div class="bg-pink-500">test3</div>
		</section>
	</div>
</main>
