
<script lang="ts">
    import { onMount } from 'svelte';

    import { insignia } from '@services';
    import { type InsigniaUser } from '@services/insignia/insignia';

    let pageNumber = 0;
    let users: InsigniaUser[] = [];

    let isLoading = true;

    onMount(async () => {
      users = [...users, ...await insignia.listUsers({ limit: 16, offset: 16 * pageNumber })];

      isLoading = false;
    });
</script>

<main class="flex justify-center">
    <div class="container">
        {#if users.length}
            <table class="table-auto text-left">
                <thead>
                    <tr class="text-gray-400">
                        <th>Id</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Phone Verified Date Time</th>
                        <th>Email Verified Date Time</th>
                    </tr>
                </thead>

                <tbody>
                  {#each users as u}
                    <tr>
                    <td>{u.id}</td>
                    <td>{u.name}</td>

                    <td>
                      {#if u.email}
                        {u.email}
                      {:else}
                        <div class="w-max rounded-md p-2 bg-blue-400 text-white font-semibold">
                          <span>
                            email not set
                          </span>
                        </div>
                      {/if}
                    </td>

                    <td>
                      {#if u.phone}
                        {u.phone}
                      {:else}
                        <div class="w-max rounded-md p-2 bg-blue-600 text-white font-semibold">
                        <span>
                            phone not set
                        </span>
                        </div>
                      {/if}
                    </td>

                    <td>{u.phoneVerifiedAt}</td>
                    <td>{u.emailVerifiedAt}</td>
                    </tr>
                  {/each}
                </tbody>
            </table>
        {:else}
            <p>
                No Users existed yet
            </p>
        {/if}
    </div>
</main>
